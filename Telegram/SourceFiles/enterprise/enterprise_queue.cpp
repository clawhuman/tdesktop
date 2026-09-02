/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "enterprise/enterprise_queue.h"

#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string_view>

namespace Enterprise {
namespace {

constexpr auto kQueueAad = std::string_view("internal-telegram/archive-queue/v1");

[[nodiscard]] QByteArray QueueKey(const QByteArray &localKey) {
	const auto context = QByteArray(kQueueAad.data(), kQueueAad.size());
	const auto digest = EVP_MD_CTX_new();
	auto result = QByteArray(32, Qt::Uninitialized);
	auto size = unsigned int();
	const auto valid = digest
		&& EVP_DigestInit_ex(digest, EVP_sha256(), nullptr) == 1
		&& EVP_DigestUpdate(digest, context.constData(), context.size()) == 1
		&& EVP_DigestUpdate(digest, localKey.constData(), localKey.size()) == 1
		&& EVP_DigestFinal_ex(
			digest,
			reinterpret_cast<unsigned char*>(result.data()),
			&size) == 1
		&& size == result.size();
	EVP_MD_CTX_free(digest);
	return valid ? result : QByteArray();
}

[[nodiscard]] bool Encrypt(
		const QByteArray &key,
		const QByteArray &nonce,
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
			nullptr) == 1
		&& EVP_EncryptInit_ex(
			context,
			nullptr,
			nullptr,
			reinterpret_cast<const unsigned char*>(key.constData()),
			reinterpret_cast<const unsigned char*>(nonce.constData())) == 1
		&& EVP_EncryptUpdate(
			context,
			nullptr,
			&written,
			reinterpret_cast<const unsigned char*>(kQueueAad.data()),
			kQueueAad.size()) == 1
		&& EVP_EncryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(ciphertext->data()),
			&written,
			reinterpret_cast<const unsigned char*>(plaintext.constData()),
			plaintext.size()) == 1
		&& ((total = written), true)
		&& EVP_EncryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(ciphertext->data()) + total,
			&written) == 1
		&& ((total += written), true)
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_GET_TAG,
			tag->size(),
			tag->data()) == 1;
	EVP_CIPHER_CTX_free(context);
	if (!result) {
		ciphertext->clear();
		tag->clear();
		return false;
	}
	ciphertext->resize(total);
	return true;
}

[[nodiscard]] std::optional<QByteArray> Decrypt(
		const QByteArray &key,
		const QByteArray &nonce,
		const QByteArray &ciphertext,
		const QByteArray &tag) {
	if (nonce.size() != 12 || tag.size() != 16) {
		return std::nullopt;
	}
	const auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return std::nullopt;
	}
	auto result = QByteArray(ciphertext.size(), Qt::Uninitialized);
	auto written = 0;
	auto total = 0;
	const auto valid = EVP_DecryptInit_ex(
			context,
			EVP_aes_256_gcm(),
			nullptr,
			nullptr,
			nullptr) == 1
		&& EVP_DecryptInit_ex(
			context,
			nullptr,
			nullptr,
			reinterpret_cast<const unsigned char*>(key.constData()),
			reinterpret_cast<const unsigned char*>(nonce.constData())) == 1
		&& EVP_DecryptUpdate(
			context,
			nullptr,
			&written,
			reinterpret_cast<const unsigned char*>(kQueueAad.data()),
			kQueueAad.size()) == 1
		&& EVP_DecryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(result.data()),
			&written,
			reinterpret_cast<const unsigned char*>(ciphertext.constData()),
			ciphertext.size()) == 1
		&& ((total = written), true)
		&& EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_TAG,
			tag.size(),
			const_cast<char*>(tag.constData())) == 1
		&& EVP_DecryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(result.data()) + total,
			&written) == 1
		&& ((total += written), true);
	EVP_CIPHER_CTX_free(context);
	if (!valid) {
		return std::nullopt;
	}
	result.resize(total);
	return result;
}

} // namespace

std::optional<QByteArray> SealArchiveQueueEvent(
		const QByteArray &localKey,
		const QByteArray &plaintext) {
	if (localKey.isEmpty()) {
		return std::nullopt;
	}
	auto key = QueueKey(localKey);
	if (key.isEmpty()) {
		return std::nullopt;
	}
	auto nonce = QByteArray(12, Qt::Uninitialized);
	if (RAND_bytes(
			reinterpret_cast<unsigned char*>(nonce.data()),
			nonce.size()) != 1) {
		OPENSSL_cleanse(key.data(), key.size());
		return std::nullopt;
	}
	auto ciphertext = QByteArray();
	auto tag = QByteArray();
	const auto encrypted = Encrypt(key, nonce, plaintext, &ciphertext, &tag);
	OPENSSL_cleanse(key.data(), key.size());
	if (!encrypted) {
		return std::nullopt;
	}
	return QJsonDocument(QJsonObject{
		{ u"version"_q, 1 },
		{ u"nonce"_q, QString::fromLatin1(nonce.toBase64()) },
		{ u"ciphertext"_q, QString::fromLatin1(ciphertext.toBase64()) },
		{ u"tag"_q, QString::fromLatin1(tag.toBase64()) },
	}).toJson(QJsonDocument::Compact);
}

std::optional<QByteArray> OpenArchiveQueueEvent(
		const QByteArray &localKey,
		const QByteArray &encoded) {
	if (localKey.isEmpty()) {
		return std::nullopt;
	}
	QJsonParseError error;
	const auto object = QJsonDocument::fromJson(encoded, &error).object();
	if (error.error != QJsonParseError::NoError
		|| object.value(u"version"_q).toInt() != 1) {
		return std::nullopt;
	}
	auto key = QueueKey(localKey);
	if (key.isEmpty()) {
		return std::nullopt;
	}
	const auto result = Decrypt(
		key,
		QByteArray::fromBase64(object.value(u"nonce"_q).toString().toLatin1()),
		QByteArray::fromBase64(object.value(u"ciphertext"_q).toString().toLatin1()),
		QByteArray::fromBase64(object.value(u"tag"_q).toString().toLatin1()));
	OPENSSL_cleanse(key.data(), key.size());
	return result;
}

} // namespace Enterprise
