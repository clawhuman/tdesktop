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

struct BuildConfig final {
	QString controlUrl;
	QString envelopeKeyId;
	QByteArray envelopePublicKey;
	QByteArray policyPublicKey;
	QByteArray caCertificate;
	QString sourceUrl;
};

[[nodiscard]] bool Enabled();
[[nodiscard]] BuildConfig Config();
[[nodiscard]] QString ValidateConfig(const BuildConfig &config);

} // namespace Enterprise
