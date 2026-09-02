/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "enterprise/enterprise_envelope.h"

#include "enterprise/enterprise_config.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <cstring>
#include <string_view>

namespace Enterprise {
namespace {

constexpr auto kEnvelopeAlgorithm = "RSA-OAEP-4096-SHA256+A256GCM";
constexpr auto kEnvelopeLabel = std::string_view("internal-telegram/envelope/v1");

[[nodiscard]] QByteArray WrapKey(
		const QByteArray &publicKeyPem,
		const QByteArray &dataKey) {
	const auto bio = BIO_new_mem_buf(
		publicKeyPem.constData(),
		publicKeyPem.size());
	const auto key = bio ? PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr) : nullptr;
	BIO_free(bio);
	if (!key
		|| EVP_PKEY_base_id(key) != EVP_PKEY_RSA
		|| EVP_PKEY_bits(key) != 4096) {
		EVP_PKEY_free(key);
		return {};
	}
	const auto context = EVP_PKEY_CTX_new(key, nullptr);
	auto label = static_cast<unsigned char*>(OPENSSL_malloc(kEnvelopeLabel.size()));
	if (label) {
		std::memcpy(label, kEnvelopeLabel.data(), kEnvelopeLabel.size());
	}
	auto wrappedSize = size_t();
	const auto initialized = context
		&& label
		&& EVP_PKEY_encrypt_init(context) > 0
		&& EVP_PKEY_CTX_set_rsa_padding(
			context,
			RSA_PKCS1_OAEP_PADDING) > 0
		&& EVP_PKEY_CTX_set_rsa_oaep_md(context, EVP_sha256()) > 0
		&& EVP_PKEY_CTX_set_rsa_mgf1_md(context, EVP_sha256()) > 0
		&& EVP_PKEY_CTX_set0_rsa_oaep_label(
			context,
			label,
			kEnvelopeLabel.size()) > 0;
	if (initialized) {
		label = nullptr;
	}
	auto result = QByteArray();
	if (initialized
		&& EVP_PKEY_encrypt(
			context,
			nullptr,
			&wrappedSize,
			reinterpret_cast<const unsigned char*>(dataKey.constData()),
			dataKey.size()) > 0) {
		result.resize(wrappedSize);
		if (EVP_PKEY_encrypt(
				context,
				reinterpret_cast<unsigned char*>(result.data()),
				&wrappedSize,
				reinterpret_cast<const unsigned char*>(dataKey.constData()),
				dataKey.size()) > 0) {
			result.resize(wrappedSize);
		} else {
			result.clear();
		}
	}
	OPENSSL_free(label);
	EVP_PKEY_CTX_free(context);
	EVP_PKEY_free(key);
	return result;
}

[[nodiscard]] bool Encrypt(
		const QByteArray &key,
		const QByteArray &nonce,
		const QByteArray &aad,
		const QByteArray &plaintext,
		QByteArray *ciphertext,
		QByteArray *tag) {
	const auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return false;
	}
	ciphertext->resize(plaintext.size());
	tag->resize(16);
	auto written = 0;
	auto total = 0;
	const auto result = EVP_EncryptInit_ex(
			context,
			EVP_aes_256_gcm(),
			nullptr,
			nullptr,
			nullptr) > 0
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_IVLEN,
			nonce.size(),
			nullptr) > 0
		&& EVP_EncryptInit_ex(
			context,
			nullptr,
			nullptr,
			reinterpret_cast<const unsigned char*>(key.constData()),
			reinterpret_cast<const unsigned char*>(nonce.constData())) > 0
		&& EVP_EncryptUpdate(
			context,
			nullptr,
			&written,
			reinterpret_cast<const unsigned char*>(aad.constData()),
			aad.size()) > 0
		&& EVP_EncryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(ciphertext->data()),
			&written,
			reinterpret_cast<const unsigned char*>(plaintext.constData()),
			plaintext.size()) > 0
		&& ((total = written), true)
		&& EVP_EncryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(ciphertext->data()) + total,
			&written) > 0
		&& ((total += written), true)
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_GET_TAG,
			tag->size(),
			tag->data()) > 0;
	EVP_CIPHER_CTX_free(context);
	if (!result) {
		ciphertext->clear();
		tag->clear();
		return false;
	}
	ciphertext->resize(total);
	return true;
}

} // namespace

std::optional<QJsonObject> SealEnvelopeV1(const QByteArray &plaintext) {
	const auto config = Config();
	auto dataKey = QByteArray(32, Qt::Uninitialized);
	auto nonce = QByteArray(12, Qt::Uninitialized);
	if (RAND_bytes(
			reinterpret_cast<unsigned char*>(dataKey.data()),
			dataKey.size()) != 1
		|| RAND_bytes(
			reinterpret_cast<unsigned char*>(nonce.data()),
			nonce.size()) != 1) {
		OPENSSL_cleanse(dataKey.data(), dataKey.size());
		return std::nullopt;
	}
	const auto wrappedKey = WrapKey(config.envelopePublicKey, dataKey);
	const auto aad = QByteArray(kEnvelopeLabel.data(), kEnvelopeLabel.size())
		+ '\0' + config.envelopeKeyId.toUtf8();
	auto ciphertext = QByteArray();
	auto tag = QByteArray();
	const auto encrypted = !wrappedKey.isEmpty()
		&& Encrypt(dataKey, nonce, aad, plaintext, &ciphertext, &tag);
	OPENSSL_cleanse(dataKey.data(), dataKey.size());
	if (!encrypted) {
		return std::nullopt;
	}
	return QJsonObject{
		{ u"version"_q, 1 },
		{ u"key_id"_q, config.envelopeKeyId },
		{ u"algorithm"_q, QString::fromLatin1(kEnvelopeAlgorithm) },
		{ u"wrapped_key"_q, QString::fromLatin1(wrappedKey.toBase64()) },
		{ u"nonce"_q, QString::fromLatin1(nonce.toBase64()) },
		{ u"ciphertext"_q, QString::fromLatin1(ciphertext.toBase64()) },
		{ u"tag"_q, QString::fromLatin1(tag.toBase64()) },
	};
}

bool VerifyEnvelopeV1TestVector() {
	const auto key = QByteArray::fromBase64(
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
	const auto nonce = QByteArray::fromBase64("AAECAwQFBgcICQoL");
	const auto plaintext = QByteArray::fromBase64(
		"ZW52ZWxvcGUtY3Jvc3MtbGFuZ3VhZ2UtdmVjdG9y");
	const auto expectedCiphertext = QByteArray::fromBase64(
		"ImygfqmKsn6gIuXkwppVAeK44EGRHDpRTgKG8XIb");
	const auto expectedTag = QByteArray::fromBase64("RgAARihceII1rXWjyRv6wg==");
	auto ciphertext = QByteArray();
	auto tag = QByteArray();
	return Encrypt(
		key,
		nonce,
		QByteArray(kEnvelopeLabel.data(), kEnvelopeLabel.size()) + '\0' + "key-1",
		plaintext,
		&ciphertext,
		&tag)
		&& ciphertext == expectedCiphertext
		&& tag == expectedTag;
}

} // namespace Enterprise
