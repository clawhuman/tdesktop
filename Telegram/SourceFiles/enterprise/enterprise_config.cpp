/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "enterprise/enterprise_config.h"

#include "enterprise/enterprise_envelope.h"
#include "enterprise/enterprise_models.h"

#include <QtCore/QUrl>

namespace Enterprise {

bool Enabled() {
#ifdef INTERNAL_TELEGRAM
	return true;
#else // INTERNAL_TELEGRAM
	return false;
#endif // INTERNAL_TELEGRAM
}

BuildConfig Config() {
#ifdef INTERNAL_TELEGRAM
	return {
		.controlUrl = QString::fromUtf8(INTERNAL_TELEGRAM_CONTROL_URL),
		.envelopeKeyId = QString::fromUtf8(INTERNAL_TELEGRAM_ENVELOPE_KEY_ID),
		.envelopePublicKey = QByteArray::fromBase64(
			INTERNAL_TELEGRAM_ENVELOPE_PUBLIC_KEY),
		.policyPublicKey = QByteArray::fromBase64(
			INTERNAL_TELEGRAM_POLICY_PUBLIC_KEY),
		.caCertificate = QByteArray::fromBase64(
			INTERNAL_TELEGRAM_CA_CERTIFICATE),
		.sourceUrl = QString::fromUtf8(INTERNAL_TELEGRAM_SOURCE_URL),
	};
#else // INTERNAL_TELEGRAM
	return {};
#endif // INTERNAL_TELEGRAM
}

QString ValidateConfig(const BuildConfig &config) {
	const auto url = QUrl(config.controlUrl);
	if (!url.isValid()
		|| (url.scheme() != u"https"_q)
		|| (url.host() != u"127.0.0.1"_q)
		|| (url.port() != 8443)) {
		return u"control URL must be https://127.0.0.1:8443"_q;
	}
	if (config.envelopePublicKey.isEmpty()) {
		return u"envelope public key is missing"_q;
	}
	if (config.envelopeKeyId.isEmpty()) {
		return u"envelope key ID is missing"_q;
	}
	if (config.policyPublicKey.size() != 32) {
		return u"Ed25519 policy public key must contain 32 bytes"_q;
	}
	if (!config.caCertificate.contains("BEGIN CERTIFICATE")) {
		return u"pinned CA certificate is invalid"_q;
	}
	if (!QUrl(config.sourceUrl).isValid()) {
		return u"corresponding source URL is invalid"_q;
	}
	if (!VerifyPolicyV1TestVector()) {
		return u"PolicyV1 cross-language test vector failed"_q;
	}
	if (!VerifyEnvelopeV1TestVector()) {
		return u"EnvelopeV1 cross-language test vector failed"_q;
	}
	return {};
}

} // namespace Enterprise
