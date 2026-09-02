/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QJsonObject>
#include <QtCore/QSet>
#include <QtCore/QString>
#include <QtCore/QStringList>

#include <optional>

namespace Enterprise {

enum class ArchiveEventKind {
	New,
	Edit,
	Delete,
};

struct ArchiveEventV1 final {
	QString eventId;
	QString companyIdentityId;
	QString telegramAccountId;
	QString peerId;
	QString messageId;
	QString senderId;
	ArchiveEventKind kind = ArchiveEventKind::New;
	int revision = 0;
	bool outgoing = false;
	QDateTime occurredAt;
	QString text;
	QJsonObject entities;
	QString replyToMessageId;
	QString forwardedFromId;
	QString mediaType;
	QString mediaName;
	qint64 mediaSize = 0;
	std::optional<QDateTime> deletedAt;
};

struct PolicyV1 final {
	quint64 version = 0;
	QDateTime issuedAt;
	QSet<QString> hiddenUserIds;
	QJsonObject privacy;
	QJsonObject sessions;
	QByteArray signature;
};

enum class ManagedLockReason {
	None,
	CompanyLoginRequired,
	DeviceApprovalRequired,
	DeviceRevoked,
	ControlUnavailable,
	ArchiveQueueFull,
	InvalidPolicy,
};

[[nodiscard]] QByteArray SerializeArchiveEvent(const ArchiveEventV1 &event);
[[nodiscard]] QString ValidateArchiveEvent(const ArchiveEventV1 &event);
[[nodiscard]] QString DeterministicEventId(const ArchiveEventV1 &event);
[[nodiscard]] std::optional<PolicyV1> ParseAndVerifyPolicy(
	const QByteArray &json,
	const QByteArray &publicKey,
	quint64 minimumVersion,
	QString *error);
[[nodiscard]] bool IsHiddenUserId(
	const PolicyV1 &policy,
	const QString &telegramUserId);
[[nodiscard]] bool VerifyPolicyV1TestVector();

} // namespace Enterprise
