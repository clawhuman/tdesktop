/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "storage/storage_domain.h"

#include "core/version.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/serialize_common.h"
#include "mtproto/mtproto_config.h"
#include "main/main_domain.h"
#include "main/main_account.h"
#include "base/random.h"
#ifdef INTERNAL_TELEGRAM
#include "enterprise/enterprise_control.h"
#endif // INTERNAL_TELEGRAM

#include <cstring>

namespace Storage {
namespace {

using namespace details;

[[nodiscard]] QString BaseGlobalPath() {
	return cWorkingDir() + u"tdata/"_q;
}

[[nodiscard]] QString ComputeKeyName(const QString &dataName) {
	// We dropped old test authorizations when migrated to multi auth.
	//return "key_" + dataName + (cTestMode() ? "[test]" : "");
	return "key_" + dataName;
}

#ifdef INTERNAL_TELEGRAM
[[nodiscard]] QString ComputeEnvelopePath(const QString &dataName) {
	return BaseGlobalPath() + u"managed_envelope_"_q + dataName + u".json"_q;
}

[[nodiscard]] QString ComputeArchiveQueuePath(const QString &dataName) {
	return BaseGlobalPath() + u"managed_archive_queue_"_q + dataName;
}

[[nodiscard]] QByteArray LocalKeyBytes(const MTP::AuthKeyPtr &key) {
	const auto data = key->data();
	return QByteArray(
		reinterpret_cast<const char*>(data.data()),
		data.size());
}

[[nodiscard]] MTP::AuthKeyPtr LocalKeyFromBytes(const QByteArray &bytes) {
	if (bytes.size() != MTP::AuthKey::kSize) {
		return nullptr;
	}
	auto data = MTP::AuthKey::Data();
	std::memcpy(data.data(), bytes.constData(), bytes.size());
	return std::make_shared<MTP::AuthKey>(data);
}

[[nodiscard]] bool ConfigureArchiveQueueForKey(
		const QString &dataName,
		const MTP::AuthKeyPtr &key) {
	auto bytes = LocalKeyBytes(key);
	const auto configured = Enterprise::ConfigureArchiveQueue(
		bytes,
		ComputeArchiveQueuePath(dataName));
	bytes.fill('\0');
	return configured;
}

[[nodiscard]] bool BindAndConfigureLocalKey(
		const QString &dataName,
		const MTP::AuthKeyPtr &key) {
	if (!ConfigureArchiveQueueForKey(dataName, key)) {
		return false;
	}
	auto bytes = LocalKeyBytes(key);
	const auto bound = Enterprise::BindLocalKeyEnvelope(
		ComputeEnvelopePath(dataName),
		bytes);
	bytes.fill('\0');
	return bound;
}
#endif // INTERNAL_TELEGRAM

} // namespace

Domain::Domain(not_null<Main::Domain*> owner, const QString &dataName)
: _owner(owner)
, _dataName(dataName) {
}

Domain::~Domain() = default;

StartResult Domain::start(const QByteArray &passcode) {
	const auto modern = startModern(passcode);
	if (modern == StartModernResult::Success) {
		if (_oldVersion < AppVersion) {
			writeAccounts();
		}
		return StartResult::Success;
	} else if (modern == StartModernResult::IncorrectPasscode) {
		return StartResult::IncorrectPasscode;
	} else if (modern == StartModernResult::Failed) {
#ifdef INTERNAL_TELEGRAM
		return StartResult::IncorrectPasscode;
#else // INTERNAL_TELEGRAM
		startFromScratch();
		return StartResult::Success;
#endif // INTERNAL_TELEGRAM
	}
	auto legacy = std::make_unique<Main::Account>(_owner, _dataName, 0);
	const auto result = legacy->legacyStart(passcode);
	if (result == StartResult::Success) {
		_oldVersion = legacy->local().oldMapVersion();
		if (!startWithSingleAccount(passcode, std::move(legacy))) {
			return StartResult::IncorrectPasscode;
		}
	}
	return result;
}

void Domain::startAdded(
		not_null<Main::Account*> account,
		std::unique_ptr<MTP::Config> config) {
	Expects(_localKey != nullptr);

	account->prepareToStartAdded(_localKey);
	account->start(std::move(config));
}

bool Domain::startWithSingleAccount(
		[[maybe_unused]] const QByteArray &passcode,
		std::unique_ptr<Main::Account> account) {
	Expects(account != nullptr);

	if (auto localKey = account->local().peekLegacyLocalKey()) {
		_localKey = std::move(localKey);
#ifdef INTERNAL_TELEGRAM
		if (!BindAndConfigureLocalKey(_dataName, _localKey)) {
			_localKey = nullptr;
			return false;
		}
		_passcodeKeySalt.clear();
		_passcodeKeyEncrypted.clear();
		_hasLocalPasscode = false;
#else // INTERNAL_TELEGRAM
		encryptLocalKey(passcode);
#endif // INTERNAL_TELEGRAM
		account->start(nullptr);
	} else {
		if (!generateLocalKey()) {
			return false;
		}
#ifdef INTERNAL_TELEGRAM
		if (auto credential = Enterprise::DownloadDefaultTelegramCredential()) {
			account->setMtpAuthorization(credential->authorization);
			credential->authorization.fill('\0');
		}
#endif // INTERNAL_TELEGRAM
		account->start(account->prepareToStart(_localKey));
	}
	_owner->accountAddedInStorage(Main::Domain::AccountWithIndex{
		.account = std::move(account)
	});
	writeAccounts();
	return true;
}

bool Domain::generateLocalKey() {
	Expects(_localKey == nullptr);
	Expects(_passcodeKeySalt.isEmpty());
	Expects(_passcodeKeyEncrypted.isEmpty());

	auto pass = QByteArray(MTP::AuthKey::kSize, Qt::Uninitialized);
	auto salt = QByteArray(LocalEncryptSaltSize, Qt::Uninitialized);
	base::RandomFill(pass.data(), pass.size());
	base::RandomFill(salt.data(), salt.size());
	_localKey = CreateLocalKey(pass, salt);

#ifdef INTERNAL_TELEGRAM
	const auto bound = BindAndConfigureLocalKey(_dataName, _localKey);
	pass.fill('\0');
	if (!bound) {
		_localKey = nullptr;
		return false;
	}
	_hasLocalPasscode = false;
#else // INTERNAL_TELEGRAM
	encryptLocalKey(QByteArray());
#endif // INTERNAL_TELEGRAM
	return true;
}

void Domain::encryptLocalKey(const QByteArray &passcode) {
	_passcodeKeySalt.resize(LocalEncryptSaltSize);
	base::RandomFill(_passcodeKeySalt.data(), _passcodeKeySalt.size());
	_passcodeKey = CreateLocalKey(passcode, _passcodeKeySalt);

	EncryptedDescriptor passKeyData(MTP::AuthKey::kSize);
	_localKey->write(passKeyData.stream);
	_passcodeKeyEncrypted = PrepareEncrypted(passKeyData, _passcodeKey);
	_hasLocalPasscode = !passcode.isEmpty();
}

Domain::StartModernResult Domain::startModern(
		const QByteArray &passcode) {
	const auto name = ComputeKeyName(_dataName);
#ifdef INTERNAL_TELEGRAM
	auto migratedToManagedEnvelope = false;
#endif // INTERNAL_TELEGRAM

	FileReadDescriptor keyData;
	if (!ReadFile(keyData, name, BaseGlobalPath())) {
		return StartModernResult::Empty;
	}
	LOG(("App Info: reading accounts info..."));

	QByteArray salt, keyEncrypted, infoEncrypted;
	keyData.stream >> salt >> keyEncrypted >> infoEncrypted;
	if (!CheckStreamStatus(keyData.stream)) {
		return StartModernResult::Failed;
	}

#ifndef INTERNAL_TELEGRAM
	if (salt.size() != LocalEncryptSaltSize) {
		LOG(("App Error: bad salt in info file, size: %1").arg(salt.size()));
		return StartModernResult::Failed;
	}
#endif // !INTERNAL_TELEGRAM

	EncryptedDescriptor info;
#ifdef INTERNAL_TELEGRAM
	const auto envelopePath = ComputeEnvelopePath(_dataName);
	if (Enterprise::HasLocalKeyEnvelope(envelopePath)) {
		auto unlocked = Enterprise::UnlockLocalKeyEnvelope(envelopePath);
		if (!unlocked) {
			return StartModernResult::Failed;
		}
		_localKey = LocalKeyFromBytes(*unlocked);
		unlocked->fill('\0');
		if (!_localKey || !ConfigureArchiveQueueForKey(_dataName, _localKey)) {
			_localKey = nullptr;
			return StartModernResult::Failed;
		}
		_passcodeKeySalt.clear();
		_passcodeKeyEncrypted.clear();
		_hasLocalPasscode = false;
	} else {
#endif // INTERNAL_TELEGRAM
	_passcodeKey = CreateLocalKey(passcode, salt);

	EncryptedDescriptor keyInnerData;
	if (!DecryptLocal(keyInnerData, keyEncrypted, _passcodeKey)) {
		LOG(("App Info: could not decrypt pass-protected key from info file, "
			"maybe bad password..."));
		return StartModernResult::IncorrectPasscode;
	}
	auto key = Serialize::read<MTP::AuthKey::Data>(keyInnerData.stream);
	if (keyInnerData.stream.status() != QDataStream::Ok
		|| !keyInnerData.stream.atEnd()) {
		LOG(("App Error: could not read pass-protected key from info file"));
		return StartModernResult::Failed;
	}
	_localKey = std::make_shared<MTP::AuthKey>(key);

	_passcodeKeyEncrypted = keyEncrypted;
	_passcodeKeySalt = salt;
	_hasLocalPasscode = !passcode.isEmpty();

#ifdef INTERNAL_TELEGRAM
		if (!BindAndConfigureLocalKey(_dataName, _localKey)) {
			_localKey = nullptr;
			return StartModernResult::Failed;
		}
		_passcodeKey = nullptr;
		_passcodeKeySalt.clear();
		_passcodeKeyEncrypted.clear();
		_hasLocalPasscode = false;
		migratedToManagedEnvelope = true;
	}
#endif // INTERNAL_TELEGRAM

	if (!DecryptLocal(info, infoEncrypted, _localKey)) {
		LOG(("App Error: could not decrypt info."));
		return StartModernResult::Failed;
	}
	LOG(("App Info: reading encrypted info..."));
	auto count = qint32();
	info.stream >> count;
	if (count <= 0 || count > Main::Domain::kPremiumMaxAccounts) {
		LOG(("App Error: bad accounts count: %1").arg(count));
		return StartModernResult::Failed;
	}

	_oldVersion = keyData.version;

	auto tried = base::flat_set<int>();
	auto sessions = base::flat_set<uint64>();
	auto active = 0;
	for (auto i = 0; i != count; ++i) {
		auto index = qint32();
		info.stream >> index;
		if (index >= 0
			&& index < Main::Domain::kPremiumMaxAccounts
			&& tried.emplace(index).second) {
			auto account = std::make_unique<Main::Account>(
				_owner,
				_dataName,
				index);
			auto config = account->prepareToStart(_localKey);
			const auto sessionId = account->willHaveSessionUniqueId(
				config.get());
			if (!sessions.contains(sessionId)
				&& (sessionId != 0 || (sessions.empty() && i + 1 == count))) {
				if (sessions.empty()) {
					active = index;
				}
				account->start(std::move(config));
				_owner->accountAddedInStorage({
					.index = index,
					.account = std::move(account)
				});
				sessions.emplace(sessionId);
			}
		}
	}
	if (sessions.empty()) {
		LOG(("App Error: no accounts read."));
		return StartModernResult::Failed;
	}

	if (!info.stream.atEnd()) {
		info.stream >> active;
	}
	_owner->activateFromStorage(active);

#ifdef INTERNAL_TELEGRAM
	if (migratedToManagedEnvelope) {
		writeAccounts();
	}
#endif // INTERNAL_TELEGRAM

	Ensures(!sessions.empty());
	return StartModernResult::Success;
}

void Domain::writeAccounts() {
	Expects(!_owner->accounts().empty());

	const auto path = BaseGlobalPath();
	if (!QDir().exists(path)) {
		QDir().mkpath(path);
	}

	FileWriteDescriptor key(ComputeKeyName(_dataName), path);
#ifdef INTERNAL_TELEGRAM
	key.writeData(QByteArray());
	key.writeData(QByteArray());
#else // INTERNAL_TELEGRAM
	key.writeData(_passcodeKeySalt);
	key.writeData(_passcodeKeyEncrypted);
#endif // INTERNAL_TELEGRAM

	const auto &list = _owner->accounts();

	auto keySize = sizeof(qint32) + sizeof(qint32) * list.size();

	EncryptedDescriptor keyData(keySize);
	keyData.stream << qint32(list.size());
	for (const auto &[index, account] : list) {
		keyData.stream << qint32(index);
	}
	keyData.stream << qint32(_owner->activeForStorage());
	key.writeEncrypted(keyData, _localKey);
}

void Domain::startFromScratch() {
	if (!startWithSingleAccount(
		QByteArray(),
		std::make_unique<Main::Account>(_owner, _dataName, 0))) {
		LOG(("App Error: could not bind the managed local key."));
	}
}

bool Domain::checkPasscode(
		[[maybe_unused]] const QByteArray &passcode) const {
#ifdef INTERNAL_TELEGRAM
	return false;
#else // INTERNAL_TELEGRAM
	Expects(!_passcodeKeySalt.isEmpty());
	Expects(_passcodeKey != nullptr);

	const auto checkKey = CreateLocalKey(passcode, _passcodeKeySalt);
	return checkKey->equals(_passcodeKey);
#endif // INTERNAL_TELEGRAM
}

void Domain::setPasscode([[maybe_unused]] const QByteArray &passcode) {
#ifdef INTERNAL_TELEGRAM
	return;
#else // INTERNAL_TELEGRAM
	Expects(!_passcodeKeySalt.isEmpty());
	Expects(_localKey != nullptr);

	encryptLocalKey(passcode);
	writeAccounts();

	_passcodeKeyChanged.fire({});
#endif // INTERNAL_TELEGRAM
}

int Domain::oldVersion() const {
	return _oldVersion;
}

void Domain::clearOldVersion() {
	_oldVersion = 0;
}

rpl::producer<> Domain::localPasscodeChanged() const {
	return _passcodeKeyChanged.events();
}

bool Domain::hasLocalPasscode() const {
	return _hasLocalPasscode;
}

} // namespace Storage
