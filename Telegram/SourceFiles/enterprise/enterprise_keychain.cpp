/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "enterprise/enterprise_keychain.h"

#ifdef Q_OS_MAC
#include <Security/Security.h>
#endif // Q_OS_MAC

namespace Enterprise {
namespace {

#ifdef Q_OS_MAC
constexpr auto kService = "com.company.internaltelegram.managed";

[[nodiscard]] CFStringRef MakeString(const QByteArray &value) {
	return CFStringCreateWithBytes(
		kCFAllocatorDefault,
		reinterpret_cast<const UInt8*>(value.constData()),
		value.size(),
		kCFStringEncodingUTF8,
		false);
}

[[nodiscard]] CFMutableDictionaryRef MakeQuery(const QString &account) {
	const auto result = CFDictionaryCreateMutable(
		kCFAllocatorDefault,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks);
	const auto service = MakeString(QByteArray(kService));
	const auto accountValue = MakeString(account.toUtf8());
	CFDictionarySetValue(result, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(result, kSecAttrService, service);
	CFDictionarySetValue(result, kSecAttrAccount, accountValue);
	CFRelease(service);
	CFRelease(accountValue);
	return result;
}
#endif // Q_OS_MAC

} // namespace

QByteArray LoadKeychainSecret(const QString &account) {
#ifdef Q_OS_MAC
	const auto query = MakeQuery(account);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef value = nullptr;
	const auto status = SecItemCopyMatching(query, &value);
	CFRelease(query);
	if (status != errSecSuccess || !value) {
		return {};
	}
	const auto data = static_cast<CFDataRef>(value);
	auto result = QByteArray(
		reinterpret_cast<const char*>(CFDataGetBytePtr(data)),
		CFDataGetLength(data));
	CFRelease(value);
	return result;
#else // Q_OS_MAC
	return {};
#endif // Q_OS_MAC
}

bool SaveKeychainSecret(
		const QString &account,
		const QByteArray &secret) {
#ifdef Q_OS_MAC
	DeleteKeychainSecret(account);
	const auto query = MakeQuery(account);
	const auto data = CFDataCreate(
		kCFAllocatorDefault,
		reinterpret_cast<const UInt8*>(secret.constData()),
		secret.size());
	CFDictionarySetValue(query, kSecValueData, data);
	const auto status = SecItemAdd(query, nullptr);
	CFRelease(data);
	CFRelease(query);
	return status == errSecSuccess;
#else // Q_OS_MAC
	return false;
#endif // Q_OS_MAC
}

void DeleteKeychainSecret(const QString &account) {
#ifdef Q_OS_MAC
	const auto query = MakeQuery(account);
	SecItemDelete(query);
	CFRelease(query);
#endif // Q_OS_MAC
}

} // namespace Enterprise
