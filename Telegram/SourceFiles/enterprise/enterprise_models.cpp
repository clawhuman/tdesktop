/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "enterprise/enterprise_models.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonValue>

#include <openssl/evp.h>

#include <algorithm>

namespace Enterprise {
namespace {

[[nodiscard]] QString KindString(ArchiveEventKind kind) {
	switch (kind) {
	case ArchiveEventKind::New: return u"new"_q;
	case ArchiveEventKind::Edit: return u"edit"_q;
	case ArchiveEventKind::Delete: return u"delete"_q;
	}
	return {};
}

[[nodiscard]] bool IsDecimalId(const QString &value) {
	if (value.isEmpty()) {
		return false;
	}
	for (const auto character : value) {
		if (!character.isDigit()) {
			return false;
		}
	}
	return value != u"0"_q;
}

[[nodiscard]] QByteArray JsonValueBytes(const QJsonValue &value) {
	auto result = QJsonDocument(QJsonArray{ value }).toJson(
		QJsonDocument::Compact);
	return result.mid(1, result.size() - 2);
}

[[nodiscard]] QByteArray CanonicalPolicyBytes(const QJsonObject &document) {
	const auto privacy = document.value(u"privacy"_q).toObject();
	const auto sessions = document.value(u"sessions"_q).toObject();
	const auto objectBytes = [](const QJsonObject &object) {
		auto keys = object.keys();
		std::sort(keys.begin(), keys.end());
		auto result = QByteArray("{");
		for (auto i = 0; i != keys.size(); ++i) {
			if (i) {
				result += ',';
			}
			result += JsonValueBytes(keys[i]);
			result += ':';
			result += JsonValueBytes(object.value(keys[i]));
		}
		return result + '}';
	};
	return QByteArray("{\"hidden_user_ids\":")
		+ JsonValueBytes(document.value(u"hidden_user_ids"_q))
		+ ",\"issued_at\":"
		+ JsonValueBytes(document.value(u"issued_at"_q))
		+ ",\"privacy\":"
		+ objectBytes(privacy)
		+ ",\"sessions\":"
		+ objectBytes(sessions)
		+ ",\"version\":"
		+ JsonValueBytes(document.value(u"version"_q))
		+ '}';
}

[[nodiscard]] bool VerifyEd25519(
		const QByteArray &publicKey,
		const QByteArray &message,
		const QByteArray &signature) {
	if (publicKey.size() != 32 || signature.size() != 64) {
		return false;
	}
	const auto key = EVP_PKEY_new_raw_public_key(
		EVP_PKEY_ED25519,
		nullptr,
		reinterpret_cast<const unsigned char*>(publicKey.constData()),
		publicKey.size());
	if (!key) {
		return false;
	}
	const auto context = EVP_MD_CTX_new();
	const auto result = context
		&& (EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1)
		&& (EVP_DigestVerify(
			context,
			reinterpret_cast<const unsigned char*>(signature.constData()),
			signature.size(),
			reinterpret_cast<const unsigned char*>(message.constData()),
			message.size()) == 1);
	EVP_MD_CTX_free(context);
	EVP_PKEY_free(key);
	return result;
}

} // namespace

QByteArray SerializeArchiveEvent(const ArchiveEventV1 &event) {
	auto object = QJsonObject{
		{ u"event_id"_q, event.eventId },
		{ u"company_identity_id"_q, event.companyIdentityId },
		{ u"telegram_account_id"_q, event.telegramAccountId },
		{ u"peer_id"_q, event.peerId },
		{ u"message_id"_q, event.messageId },
		{ u"sender_id"_q, event.senderId },
		{ u"kind"_q, KindString(event.kind) },
		{ u"revision"_q, event.revision },
		{ u"outgoing"_q, event.outgoing },
		{ u"occurred_at"_q, event.occurredAt.toUTC().toString(Qt::ISODateWithMs) },
		{ u"text"_q, event.text },
		{ u"entities"_q, event.entities },
		{ u"reply_to_message_id"_q, event.replyToMessageId },
		{ u"forwarded_from_id"_q, event.forwardedFromId },
		{ u"media_type"_q, event.mediaType },
		{ u"media_name"_q, event.mediaName },
		{ u"media_size"_q, double(event.mediaSize) },
	};
	if (event.deletedAt) {
		object.insert(
			u"deleted_at"_q,
			event.deletedAt->toUTC().toString(Qt::ISODateWithMs));
	}
	return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

QString ValidateArchiveEvent(const ArchiveEventV1 &event) {
	if (event.eventId.isEmpty()
		|| event.companyIdentityId.isEmpty()
		|| !IsDecimalId(event.telegramAccountId)
		|| !IsDecimalId(event.peerId)
		|| !IsDecimalId(event.messageId)
		|| !IsDecimalId(event.senderId)) {
		return u"archive identifiers are incomplete"_q;
	}
	if (event.revision < 0 || !event.occurredAt.isValid()) {
		return u"archive revision or timestamp is invalid"_q;
	}
	if (event.mediaSize < 0) {
		return u"archive media size is invalid"_q;
	}
	return {};
}

QString DeterministicEventId(const ArchiveEventV1 &event) {
	const auto material = event.telegramAccountId.toUtf8()
		+ ':' + event.peerId.toUtf8()
		+ ':' + event.messageId.toUtf8()
		+ ':' + KindString(event.kind).toUtf8()
		+ ':' + QByteArray::number(event.revision);
	return QString::fromLatin1(QCryptographicHash::hash(
		material,
		QCryptographicHash::Sha256).toHex());
}

std::optional<PolicyV1> ParseAndVerifyPolicy(
		const QByteArray &json,
		const QByteArray &publicKey,
		quint64 minimumVersion,
		QString *error) {
	const auto fail = [&](QString text) -> std::optional<PolicyV1> {
		if (error) {
			*error = std::move(text);
		}
		return std::nullopt;
	};
	QJsonParseError parseError;
	const auto root = QJsonDocument::fromJson(json, &parseError).object();
	if (parseError.error != QJsonParseError::NoError || root.isEmpty()) {
		return fail(u"policy JSON is invalid"_q);
	}
	const auto signature = QByteArray::fromBase64(
		root.value(u"signature"_q).toString().toLatin1());
	auto document = root;
	document.remove(u"signature"_q);
	const auto version = document.value(u"version"_q).toVariant().toULongLong();
	if (!version || version < minimumVersion) {
		return fail(u"policy version is invalid or lower than the applied version"_q);
	}
	if (!VerifyEd25519(publicKey, CanonicalPolicyBytes(document), signature)) {
		return fail(u"policy signature is invalid"_q);
	}
	auto result = PolicyV1{
		.version = version,
		.issuedAt = QDateTime::fromString(
			document.value(u"issued_at"_q).toString(),
			Qt::ISODate),
		.privacy = document.value(u"privacy"_q).toObject(),
		.sessions = document.value(u"sessions"_q).toObject(),
		.signature = signature,
	};
	if (!result.issuedAt.isValid()) {
		return fail(u"policy issue time is invalid"_q);
	}
	for (const auto &value : document.value(u"hidden_user_ids"_q).toArray()) {
		const auto id = value.toString();
		if (!IsDecimalId(id)) {
			return fail(u"policy contains an invalid hidden user ID"_q);
		}
		result.hiddenUserIds.insert(id);
	}
	if (error) {
		error->clear();
	}
	return result;
}

bool IsHiddenUserId(
		const PolicyV1 &policy,
		const QString &telegramUserId) {
	return policy.hiddenUserIds.contains(telegramUserId);
}

bool VerifyPolicyV1TestVector() {
	const auto publicKey = QByteArray::fromBase64(
		"A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=");
	const auto document = QByteArray(
		R"({"hidden_user_ids":["1234567890123456789","42"],"issued_at":"2023-11-14T22:13:20Z","privacy":{"bio":"nobody","birthday":"contacts","calls":"nobody","forwards":"contacts","group_invites":"everyone","last_seen":"nobody","phone_number":"contacts","profile_photo":"everyone","unknown_messages":"contacts","voice_messages":"contacts"},"sessions":{"auto_terminate_days":90,"terminate_all_other":true,"terminate_session_ids":["9001","9002"]},"version":7,"signature":"JT2vVgyZDFoUB0oSmmqbw6ALoi9zZ4ie77RtKR3ZRzpR04WYVaBRXpzNVonVEZRckNujLWJGqNw+50jOdKVQCA=="})");
	auto error = QString();
	const auto policy = ParseAndVerifyPolicy(
		document,
		publicKey,
		7,
		&error);
	return policy
		&& policy->version == 7
		&& IsHiddenUserId(*policy, u"1234567890123456789"_q)
		&& IsHiddenUserId(*policy, u"42"_q);
}

} // namespace Enterprise
