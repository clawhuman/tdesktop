/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "enterprise/enterprise_control.h"

#include "enterprise/enterprise_archive.h"
#include "enterprise/enterprise_config.h"
#include "enterprise/enterprise_envelope.h"
#include "enterprise/enterprise_keychain.h"
#include "enterprise/enterprise_queue.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QEventLoop>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QFile>
#include <QtCore/QSaveFile>
#include <QtCore/QSettings>
#include <QtCore/QTimer>
#include <QtCore/QUuid>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslSocket>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>

#include <algorithm>
#include <memory>
#include <utility>

namespace Enterprise {
namespace {

const auto kRefreshTokenAccount = u"refresh-token"_q;
constexpr auto kRequestTimeout = crl::time(15000);
constexpr auto kHeartbeatInterval = crl::time(60000);
constexpr auto kUnavailableLimit = crl::time(300000);
constexpr auto kArchiveBatchInterval = crl::time(1000);
constexpr auto kArchiveMaxEvents = 50000;
constexpr auto kArchiveMaxBytes = 100 * 1024 * 1024;

struct Response final {
	int status = 0;
	QByteArray body;
	bool networkError = false;
};

struct ArchiveQueueItem final {
	QString path;
	qint64 bytes = 0;
};

struct State final {
	std::unique_ptr<QNetworkAccessManager> network;
	std::unique_ptr<QTimer> heartbeat;
	std::unique_ptr<QTimer> archiveFlush;
	QByteArray accessToken;
	QDateTime accessExpiresAt;
	QByteArray refreshToken;
	QString companyIdentity;
	QString deviceId;
	QDateTime lastControlSuccess;
	quint64 policyVersion = 0;
	std::function<void(QString)> lock;
	QByteArray archiveKey;
	QString archiveDirectory;
	QVector<ArchiveQueueItem> archiveQueue;
	qint64 archiveBytes = 0;
};

[[nodiscard]] State &Current() {
	static auto result = State();
	return result;
}

[[nodiscard]] QNetworkRequest Request(
		const QString &path,
		const QByteArray &requestId = {}) {
	const auto config = Config();
	auto request = QNetworkRequest(QUrl(config.controlUrl + path));
	request.setHeader(QNetworkRequest::ContentTypeHeader, u"application/json"_q);
	request.setRawHeader("Cache-Control", "no-store");
	request.setRawHeader("Pragma", "no-cache");
	request.setRawHeader(
		"X-Request-ID",
		requestId.isEmpty()
			? QUuid::createUuid().toString(QUuid::WithoutBraces).toUtf8()
			: requestId);
	if (!Current().accessToken.isEmpty()) {
		request.setRawHeader(
			"Authorization",
			QByteArray("Bearer ") + Current().accessToken);
	}
	const auto certificates = QSslCertificate::fromData(config.caCertificate);
	if (!certificates.isEmpty()) {
		auto ssl = QSslConfiguration::defaultConfiguration();
		ssl.setCaCertificates(certificates);
		ssl.setPeerVerifyMode(QSslSocket::VerifyPeer);
		request.setSslConfiguration(ssl);
	}
	return request;
}

[[nodiscard]] Response Send(
		const QString &method,
		const QString &path,
		const QJsonObject &body = {},
		const QByteArray &requestId = {}) {
	auto &state = Current();
	if (!state.network) {
		state.network = std::make_unique<QNetworkAccessManager>();
	}
	auto request = Request(path, requestId);
	const auto encoded = QJsonDocument(body).toJson(QJsonDocument::Compact);
	auto reply = (method == u"GET"_q)
		? state.network->get(request)
		: state.network->post(request, encoded);
	auto loop = QEventLoop();
	auto timer = QTimer();
	timer.setSingleShot(true);
	QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
	QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
	timer.start(kRequestTimeout);
	loop.exec();
	if (!reply->isFinished()) {
		reply->abort();
	}
	const auto result = Response{
		.status = reply->attribute(
			QNetworkRequest::HttpStatusCodeAttribute).toInt(),
		.body = reply->readAll(),
		.networkError = reply->error() != QNetworkReply::NoError,
	};
	reply->deleteLater();
	return result;
}

[[nodiscard]] QString ErrorText(const Response &response) {
	const auto object = QJsonDocument::fromJson(response.body).object();
	const auto error = object.value(u"error"_q).toString();
	return error.isEmpty()
		? u"The company control service could not complete the request."_q
		: error;
}

[[nodiscard]] bool StoreTokens(const QJsonObject &object) {
	auto &state = Current();
	const auto accessToken = object.value(u"access_token"_q).toString().toUtf8();
	const auto refreshToken = object.value(u"refresh_token"_q).toString().toUtf8();
	const auto accessExpiresAt = QDateTime::fromString(
		object.value(u"access_expires_at"_q).toString(),
		Qt::ISODate);
	if (accessToken.isEmpty()
		|| refreshToken.isEmpty()
		|| !accessExpiresAt.isValid()
		|| !SaveKeychainSecret(kRefreshTokenAccount, refreshToken)) {
		return false;
	}
	state.accessToken = accessToken;
	state.refreshToken = refreshToken;
	state.accessExpiresAt = accessExpiresAt;
	state.lastControlSuccess = QDateTime::currentDateTimeUtc();
	return true;
}

[[nodiscard]] bool RefreshAccessToken() {
	auto &state = Current();
	const auto refresh = state.refreshToken.isEmpty()
		? LoadKeychainSecret(kRefreshTokenAccount)
		: state.refreshToken;
	if (refresh.isEmpty()) {
		return false;
	}
	state.accessToken.clear();
	const auto response = Send(u"POST"_q, u"/api/v1/client/auth/refresh"_q, {
		{ u"refresh_token"_q, QString::fromUtf8(refresh) },
	});
	if (response.status != 200) {
		DeleteKeychainSecret(kRefreshTokenAccount);
		state.refreshToken.clear();
		return false;
	}
	return StoreTokens(QJsonDocument::fromJson(response.body).object());
}

[[nodiscard]] bool LoadPolicy(QString *error) {
	auto &state = Current();
	const auto response = Send(u"GET"_q, u"/api/v1/client/policy/current"_q);
	if (response.status != 200) {
		*error = ErrorText(response);
		return false;
	}
	auto verifyError = QString();
	const auto policy = ParseAndVerifyPolicy(
		response.body,
		Config().policyPublicKey,
		state.policyVersion,
		&verifyError);
	if (!policy) {
		*error = verifyError;
		return false;
	}
	state.policyVersion = policy->version;
	ApplyPolicy(*policy);
	const auto ack = Send(u"POST"_q, u"/api/v1/client/policy/ack"_q, {
		{ u"version"_q, double(policy->version) },
		{ u"status"_q, u"applied"_q },
		{ u"error_text"_q, QString() },
	});
	if (ack.status != 200) {
		*error = ErrorText(ack);
		return false;
	}
	state.lastControlSuccess = QDateTime::currentDateTimeUtc();
	return true;
}

[[nodiscard]] bool LoginInteractively() {
	auto &state = Current();
	auto dialog = QDialog();
	dialog.setWindowTitle(u"Internal Telegram — Company sign-in"_q);
	auto layout = new QVBoxLayout(&dialog);
	auto disclosure = new QLabel(
		u"This is an enterprise-managed client. Message text and metadata "
		u"received by this client are archived for 180 days. Media binaries, "
		u"keyboard input, screens, and other applications are not collected."_q,
		&dialog);
	disclosure->setWordWrap(true);
	layout->addWidget(disclosure);
	auto form = new QFormLayout();
	auto username = new QLineEdit(&dialog);
	auto password = new QLineEdit(&dialog);
	auto totp = new QLineEdit(&dialog);
	password->setEchoMode(QLineEdit::Password);
	totp->setInputMethodHints(Qt::ImhDigitsOnly);
	form->addRow(u"Company account"_q, username);
	form->addRow(u"Password"_q, password);
	form->addRow(u"TOTP code"_q, totp);
	layout->addLayout(form);
	auto status = new QLabel(&dialog);
	status->setWordWrap(true);
	layout->addWidget(status);
	auto buttons = new QDialogButtonBox(
		QDialogButtonBox::Cancel,
		Qt::Horizontal,
		&dialog);
	auto submit = buttons->addButton(
		u"Sign in"_q,
		QDialogButtonBox::AcceptRole);
	layout->addWidget(buttons);
	QObject::connect(
		buttons,
		&QDialogButtonBox::rejected,
		&dialog,
		&QDialog::reject);
	QObject::connect(submit, &QPushButton::clicked, &dialog, [&] {
		status->setText(u"Verifying company account…"_q);
		const auto loginBody = QJsonObject{
			{ u"username"_q, username->text() },
			{ u"password"_q, password->text() },
			{ u"totp"_q, totp->text() },
			{ u"device_id"_q, state.deviceId },
		};
		const auto response = Send(
			u"POST"_q,
			u"/api/v1/client/auth/login"_q,
			loginBody);
		if (response.status == 200) {
			state.companyIdentity = username->text();
			if (StoreTokens(QJsonDocument::fromJson(response.body).object())) {
				auto settings = QSettings(
					u"Company"_q,
					u"Internal Telegram Managed"_q);
				settings.setValue(
					u"company-identity"_q,
					state.companyIdentity);
				settings.sync();
				dialog.accept();
				return;
			}
			status->setText(u"The refresh token could not be saved to Keychain."_q);
			return;
		}
		if (response.status == 403) {
			auto registration = loginBody;
			registration.insert(u"name"_q, u"Internal Telegram on macOS"_q);
			registration.insert(u"platform"_q, u"macos-arm64"_q);
			const auto registered = Send(
				u"POST"_q,
				u"/api/v1/client/devices/register"_q,
				registration);
			status->setText((registered.status == 202)
				? u"This device is registered and waiting for administrator approval. "
					u"Device ID: %1"_q.arg(state.deviceId)
				: ErrorText(registered));
			return;
		}
		status->setText(ErrorText(response));
	});
	return dialog.exec() == QDialog::Accepted;
}

void LockForArchiveFailure(const QString &reason) {
	if (const auto &lock = Current().lock) {
		lock(reason);
	}
}

[[nodiscard]] bool LoadArchiveQueue() {
	auto &state = Current();
	if (state.archiveDirectory.isEmpty()
		|| !QDir().mkpath(state.archiveDirectory)
		|| !QFile::setPermissions(
			state.archiveDirectory,
			QFileDevice::ReadOwner
				| QFileDevice::WriteOwner
				| QFileDevice::ExeOwner)) {
		return false;
	}
	state.archiveQueue.clear();
	state.archiveBytes = 0;
	const auto files = QDir(state.archiveDirectory).entryInfoList(
		{ u"*.queue"_q },
		QDir::Files,
		QDir::Name);
	for (const auto &file : files) {
		if (file.size() <= 0
			|| state.archiveQueue.size() >= kArchiveMaxEvents
			|| state.archiveBytes > (kArchiveMaxBytes - file.size())) {
			return false;
		}
		state.archiveQueue.push_back({
			.path = file.absoluteFilePath(),
			.bytes = file.size(),
		});
		state.archiveBytes += file.size();
	}
	return true;
}

[[nodiscard]] bool PersistArchiveEvent(const QByteArray &event) {
	auto &state = Current();
	const auto encrypted = SealArchiveQueueEvent(state.archiveKey, event);
	if (!encrypted) {
		return false;
	}
	const auto name = QString::number(
		QDateTime::currentMSecsSinceEpoch()).rightJustified(20, u'0')
		+ u"-"_q
		+ QUuid::createUuid().toString(QUuid::WithoutBraces)
		+ u".queue"_q;
	const auto path = QDir(state.archiveDirectory).filePath(name);
	auto file = QSaveFile(path);
	if (!file.open(QIODevice::WriteOnly)
		|| file.write(*encrypted) != encrypted->size()
		|| !file.commit()
		|| !QFile::setPermissions(
			path,
			QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
		return false;
	}
	state.archiveQueue.push_back({
		.path = path,
		.bytes = encrypted->size(),
	});
	state.archiveBytes += encrypted->size();
	return true;
}

[[nodiscard]] std::optional<QJsonObject> ReadArchiveEvent(
		const ArchiveQueueItem &item) {
	auto file = QFile(item.path);
	if (!file.open(QIODevice::ReadOnly)) {
		return std::nullopt;
	}
	const auto encrypted = file.read(kArchiveMaxBytes + 1);
	if (!file.atEnd()) {
		return std::nullopt;
	}
	const auto decrypted = OpenArchiveQueueEvent(Current().archiveKey, encrypted);
	if (!decrypted) {
		return std::nullopt;
	}
	QJsonParseError error;
	const auto event = QJsonDocument::fromJson(*decrypted, &error).object();
	return (error.error == QJsonParseError::NoError && !event.isEmpty())
		? std::optional<QJsonObject>(event)
		: std::nullopt;
}

[[nodiscard]] QByteArray ArchiveRequestId(const QJsonArray &events) {
	auto material = QByteArray();
	for (const auto &value : events) {
		material += value.toObject().value(u"event_id"_q).toString().toUtf8();
		material += '\n';
	}
	return QByteArray("archive-") + QCryptographicHash::hash(
		material,
		QCryptographicHash::Sha256).toHex();
}

void FlushArchive() {
	auto &state = Current();
	if (state.archiveQueue.isEmpty() || state.accessToken.isEmpty()) {
		return;
	}
	if (state.archiveKey.isEmpty()) {
		LockForArchiveFailure(u"The managed archive queue encryption key is unavailable."_q);
		return;
	}
	const auto count = std::min(state.archiveQueue.size(), qsizetype(100));
	auto events = QJsonArray();
	for (auto i = 0; i != count; ++i) {
		const auto event = ReadArchiveEvent(state.archiveQueue[i]);
		if (!event) {
			LockForArchiveFailure(u"A managed archive queue file is invalid or unreadable."_q);
			return;
		}
		events.append(*event);
	}
	const auto response = Send(
		u"POST"_q,
		u"/api/v1/client/archive/batch"_q,
		{ { u"events"_q, events } },
		ArchiveRequestId(events));
	if (response.status != 200) {
		return;
	}
	for (auto i = 0; i != count; ++i) {
		const auto item = state.archiveQueue.front();
		if (!QFile::remove(item.path)) {
			LockForArchiveFailure(u"A managed archive queue file could not be removed."_q);
			return;
		}
		state.archiveBytes -= item.bytes;
		state.archiveQueue.pop_front();
	}
}

void QueueArchive(ArchiveEventV1 event) {
	const auto encoded = SerializeArchiveEvent(event);
	if (!ValidateArchiveEvent(event).isEmpty()) {
		return;
	}
	if (!PersistArchiveEvent(encoded)) {
		LockForArchiveFailure(u"The managed archive event could not be encrypted and saved."_q);
		return;
	}
	const auto &state = Current();
	if (state.archiveQueue.size() >= kArchiveMaxEvents
		|| state.archiveBytes >= kArchiveMaxBytes) {
		LockForArchiveFailure(u"The managed archive queue reached its safety limit."_q);
	}
}

void Heartbeat() {
	auto &state = Current();
	const auto now = QDateTime::currentDateTimeUtc();
	if (state.accessExpiresAt < now.addSecs(120) && !RefreshAccessToken()) {
		if (state.lock) {
			state.lock(u"Company authentication expired or was revoked."_q);
		}
		return;
	}
	const auto response = Send(
		u"POST"_q,
		u"/api/v1/client/devices/heartbeat"_q);
	if (response.status == 401 || response.status == 403) {
		if (state.lock) {
			state.lock(u"This managed device was revoked."_q);
		}
		return;
	}
	if (response.status == 200) {
		state.lastControlSuccess = now;
		auto error = QString();
		if (!LoadPolicy(&error) && state.lock) {
			state.lock(error);
		}
		return;
	}
	if (state.lastControlSuccess.msecsTo(now) >= kUnavailableLimit
		&& state.lock) {
		state.lock(u"The company control service has been unavailable for five minutes."_q);
	}
}

} // namespace

bool BootstrapBeforeLocalStorage() {
	auto &state = Current();
	const auto configError = ValidateConfig(Config());
	if (!configError.isEmpty()) {
		return false;
	}
	auto settings = QSettings(
		u"Company"_q,
		u"Internal Telegram Managed"_q);
	state.deviceId = settings.value(u"device-id"_q).toString();
	state.companyIdentity = settings.value(u"company-identity"_q).toString();
	if (state.deviceId.isEmpty()) {
		state.deviceId = QUuid::createUuid().toString(QUuid::WithoutBraces);
		settings.setValue(u"device-id"_q, state.deviceId);
		settings.sync();
	}
	if (!RefreshAccessToken() && !LoginInteractively()) {
		return false;
	}
	auto policyError = QString();
	return LoadPolicy(&policyError);
}

void StartRuntimeControl(std::function<void(QString)> lock) {
	auto &state = Current();
	state.lock = std::move(lock);
	state.heartbeat = std::make_unique<QTimer>();
	state.heartbeat->setInterval(kHeartbeatInterval);
	QObject::connect(state.heartbeat.get(), &QTimer::timeout, [] {
		Heartbeat();
	});
	state.heartbeat->start();
	state.archiveFlush = std::make_unique<QTimer>();
	state.archiveFlush->setInterval(kArchiveBatchInterval);
	QObject::connect(state.archiveFlush.get(), &QTimer::timeout, [] {
		FlushArchive();
	});
	state.archiveFlush->start();
}

[[nodiscard]] bool EnsureAccountEnrollment(
		const QString &telegramAccountId,
		const QString &displayName) {
	auto settings = QSettings(
		u"Company"_q,
		u"Internal Telegram Managed"_q);
	const auto consentKey = u"telegram-consent/"_q + telegramAccountId;
	if (!settings.value(consentKey).toBool()) {
		auto dialog = QDialog();
		dialog.setWindowTitle(u"Internal Telegram — Managed account consent"_q);
		auto layout = new QVBoxLayout(&dialog);
		auto disclosure = new QLabel(
			u"This Telegram account will be used in enterprise-managed mode. "
			u"Message text and metadata received by this client are archived for "
			u"180 days. Media binaries are not archived. Continue only if you "
			u"consent to these terms."_q,
			&dialog);
		disclosure->setWordWrap(true);
		layout->addWidget(disclosure);
		auto buttons = new QDialogButtonBox(
			QDialogButtonBox::Cancel,
			Qt::Horizontal,
			&dialog);
		buttons->addButton(u"I consent"_q, QDialogButtonBox::AcceptRole);
		layout->addWidget(buttons);
		QObject::connect(
			buttons,
			&QDialogButtonBox::accepted,
			&dialog,
			&QDialog::accept);
		QObject::connect(
			buttons,
			&QDialogButtonBox::rejected,
			&dialog,
			&QDialog::reject);
		if (dialog.exec() != QDialog::Accepted) {
			return false;
		}
	}
	const auto response = Send(
		u"POST"_q,
		u"/api/v1/client/telegram/accounts/enroll"_q,
		{
			{ u"id"_q, telegramAccountId },
			{ u"display_name"_q, displayName.isEmpty()
				? u"Telegram account "_q + telegramAccountId
				: displayName },
			{ u"phone_hint"_q, QString() },
			{ u"consent_accepted"_q, true },
			{ u"consented_at"_q, QDateTime::currentDateTimeUtc().toString(
				Qt::ISODateWithMs) },
		});
	if (response.status != 201) {
		return false;
	}
	settings.setValue(consentKey, true);
	settings.sync();
	return true;
}

void AttachTelegramAccount(
		const QString &telegramAccountId,
		const QString &displayName,
		const QByteArray &authorization) {
	auto &state = Current();
	if (telegramAccountId.isEmpty()) {
		ClearArchive();
		return;
	}
	if (!EnsureAccountEnrollment(telegramAccountId, displayName)) {
		ClearArchive();
		LockForArchiveFailure(
			u"Telegram account enrollment or archive consent was not completed."_q);
		return;
	}
	ConfigureArchive(
		state.companyIdentity,
		telegramAccountId,
		[](ArchiveEventV1 event) {
			QueueArchive(std::move(event));
		});
	UploadTelegramCredential(telegramAccountId, authorization);
}

bool ConfigureArchiveQueue(
		const QByteArray &localKey,
		const QString &directory) {
	if (localKey.isEmpty() || directory.isEmpty()) {
		return false;
	}
	auto &state = Current();
	state.archiveKey.fill('\0');
	state.archiveKey = localKey;
	state.archiveDirectory = directory;
	if (LoadArchiveQueue()) {
		return true;
	}
	state.archiveKey.fill('\0');
	state.archiveKey.clear();
	state.archiveDirectory.clear();
	state.archiveQueue.clear();
	state.archiveBytes = 0;
	return false;
}

std::optional<DownloadedTelegramCredential> DownloadDefaultTelegramCredential() {
	const auto response = Send(
		u"GET"_q,
		u"/api/v1/client/telegram/credentials/download"_q);
	if (response.status == 404) {
		return std::nullopt;
	}
	const auto object = QJsonDocument::fromJson(response.body).object();
	const auto account = object.value(u"account"_q).toObject();
	const auto authorization = QByteArray::fromBase64(
		object.value(u"authorization"_q).toString().toLatin1());
	const auto accountId = account.value(u"id"_q).toString();
	if (response.status != 200 || accountId.isEmpty() || authorization.isEmpty()) {
		return std::nullopt;
	}
	return DownloadedTelegramCredential{
		.telegramAccountId = accountId,
		.authorization = authorization,
	};
}

void UploadTelegramCredential(
		const QString &telegramAccountId,
		const QByteArray &authorization) {
	if (telegramAccountId.isEmpty() || authorization.isEmpty()) {
		return;
	}
	const auto envelope = SealEnvelopeV1(authorization);
	if (!envelope) {
		return;
	}
	auto settings = QSettings(
		u"Company"_q,
		u"Internal Telegram Managed"_q);
	const auto versionKey = u"telegram-credential-version/"_q + telegramAccountId;
	const auto digestKey = u"telegram-credential-digest/"_q + telegramAccountId;
	const auto digest = QCryptographicHash::hash(
		authorization,
		QCryptographicHash::Sha256);
	if (settings.value(digestKey).toByteArray() == digest) {
		return;
	}
	const auto version = settings.value(versionKey).toInt() + 1;
	const auto response = Send(
		u"POST"_q,
		u"/api/v1/client/telegram/credentials/upload"_q,
		{
			{ u"telegram_account_id"_q, telegramAccountId },
			{ u"version"_q, version },
			{ u"envelope"_q, *envelope },
		});
	if (response.status == 200) {
		settings.setValue(versionKey, version);
		settings.setValue(digestKey, digest);
		settings.sync();
	}
}

void StopRuntimeControl() {
	auto &state = Current();
	state.heartbeat.reset();
	state.archiveFlush.reset();
	ClearArchive();
	state.archiveKey.fill('\0');
	state.archiveKey.clear();
	state.archiveDirectory.clear();
	state.archiveQueue.clear();
	state.archiveBytes = 0;
	state.accessToken.fill('\0');
	state.refreshToken.fill('\0');
	state.accessToken.clear();
	state.refreshToken.clear();
	state.network.reset();
	state.lock = {};
}

bool HasLocalKeyEnvelope(const QString &path) {
	return QFileInfo::exists(path);
}

bool BindLocalKeyEnvelope(
		const QString &path,
		const QByteArray &localKey) {
	if (!QDir().mkpath(QFileInfo(path).absolutePath())) {
		return false;
	}
	const auto envelope = SealEnvelopeV1(localKey);
	if (!envelope) {
		return false;
	}
	const auto response = Send(
		u"POST"_q,
		u"/api/v1/client/storage/bind-envelope"_q,
		{ { u"envelope"_q, *envelope } });
	if (response.status != 200) {
		return false;
	}
	auto file = QSaveFile(path);
	if (!file.open(QIODevice::WriteOnly)) {
		return false;
	}
	const auto encoded = QJsonDocument(*envelope).toJson(QJsonDocument::Compact);
	if (file.write(encoded) != encoded.size() || !file.commit()) {
		return false;
	}
	return QFile::setPermissions(
		path,
		QFileDevice::ReadOwner | QFileDevice::WriteOwner);
}

std::optional<QByteArray> UnlockLocalKeyEnvelope(const QString &path) {
	auto file = QFile(path);
	if (!file.open(QIODevice::ReadOnly)) {
		return std::nullopt;
	}
	const auto encoded = file.read(1024 * 1024);
	if (!file.atEnd()) {
		return std::nullopt;
	}
	QJsonParseError parseError;
	const auto envelope = QJsonDocument::fromJson(encoded, &parseError).object();
	if (parseError.error != QJsonParseError::NoError || envelope.isEmpty()) {
		return std::nullopt;
	}
	const auto response = Send(
		u"POST"_q,
		u"/api/v1/client/storage/unlock"_q,
		{ { u"envelope"_q, envelope } });
	if (response.status != 200) {
		return std::nullopt;
	}
	const auto localKey = QByteArray::fromBase64(
		QJsonDocument::fromJson(response.body).object()
			.value(u"local_key"_q).toString().toLatin1());
	return localKey.isEmpty()
		? std::nullopt
		: std::optional<QByteArray>(localKey);
}

} // namespace Enterprise
