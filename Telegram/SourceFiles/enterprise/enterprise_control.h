/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <functional>
#include <optional>

namespace Enterprise {

struct DownloadedTelegramCredential final {
	QString telegramAccountId;
	QByteArray authorization;
};

[[nodiscard]] bool BootstrapBeforeLocalStorage();
void StartRuntimeControl(std::function<void(QString)> lock);
void AttachTelegramAccount(
	const QString &telegramAccountId,
	const QString &displayName,
	const QByteArray &authorization);
void StopRuntimeControl();
[[nodiscard]] bool HasLocalKeyEnvelope(const QString &path);
[[nodiscard]] bool BindLocalKeyEnvelope(
	const QString &path,
	const QByteArray &localKey);
[[nodiscard]] std::optional<QByteArray> UnlockLocalKeyEnvelope(
	const QString &path);
[[nodiscard]] bool ConfigureArchiveQueue(
	const QByteArray &localKey,
	const QString &directory);
[[nodiscard]] std::optional<DownloadedTelegramCredential>
DownloadDefaultTelegramCredential();
void UploadTelegramCredential(
	const QString &telegramAccountId,
	const QByteArray &authorization);

} // namespace Enterprise
