/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "enterprise/enterprise_models.h"

#include <functional>

class HistoryItem;

namespace Enterprise {

using ArchiveSink = std::function<void(ArchiveEventV1)>;

void ConfigureArchive(
	QString companyIdentityId,
	QString telegramAccountId,
	ArchiveSink sink);
void ClearArchive();
void ApplyPolicy(PolicyV1 policy);
[[nodiscard]] bool ShouldHide(const HistoryItem *item);
void ArchiveNew(const HistoryItem *item);
void ArchiveEdit(const HistoryItem *item);
void ArchiveDelete(const HistoryItem *item);

} // namespace Enterprise
