/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>

#include <optional>

namespace Enterprise {

[[nodiscard]] std::optional<QByteArray> SealArchiveQueueEvent(
	const QByteArray &localKey,
	const QByteArray &plaintext);
[[nodiscard]] std::optional<QByteArray> OpenArchiveQueueEvent(
	const QByteArray &localKey,
	const QByteArray &encoded);

} // namespace Enterprise
