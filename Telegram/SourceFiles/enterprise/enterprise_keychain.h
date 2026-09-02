/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace Enterprise {

[[nodiscard]] QByteArray LoadKeychainSecret(const QString &account);
[[nodiscard]] bool SaveKeychainSecret(
	const QString &account,
	const QByteArray &secret);
void DeleteKeychainSecret(const QString &account);

} // namespace Enterprise
