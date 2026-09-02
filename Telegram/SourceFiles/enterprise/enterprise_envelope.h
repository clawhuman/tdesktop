/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QJsonObject>

#include <optional>

namespace Enterprise {

[[nodiscard]] std::optional<QJsonObject> SealEnvelopeV1(
	const QByteArray &plaintext);
[[nodiscard]] bool VerifyEnvelopeV1TestVector();

} // namespace Enterprise
