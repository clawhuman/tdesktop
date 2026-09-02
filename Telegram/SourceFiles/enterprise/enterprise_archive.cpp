/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "enterprise/enterprise_archive.h"

#include "data/data_document.h"
#include "data/data_media_types.h"
#include "data/data_peer.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_components.h"

#include <QtCore/QDateTime>
#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>

#include <utility>

namespace Enterprise {
namespace {

struct State final {
	QMutex mutex;
	QString companyIdentityId;
	QString telegramAccountId;
	ArchiveSink sink;
	PolicyV1 policy;
	QHash<QString, int> revisions;
};

[[nodiscard]] State &Current() {
	static auto result = State();
	return result;
}

[[nodiscard]] QString BarePeerId(PeerId id) {
	return QString::number(id.value & PeerId::kChatTypeMask);
}

[[nodiscard]] QString MessageKey(
		const QString &accountId,
		const HistoryItem *item) {
	return accountId
		+ ':' + BarePeerId(item->history()->peer->id)
		+ ':' + QString::number(item->id.bare);
}

[[nodiscard]] bool HiddenPeer(
		const PolicyV1 &policy,
		const PeerData *peer) {
	return peer
		&& peerIsUser(peer->id)
		&& IsHiddenUserId(policy, BarePeerId(peer->id));
}

[[nodiscard]] ArchiveEventV1 BuildEvent(
		const HistoryItem *item,
		ArchiveEventKind kind,
		int revision,
		const QString &companyIdentityId,
		const QString &telegramAccountId) {
	const auto now = QDateTime::currentDateTimeUtc();
	const auto forwarded = item->originalSender();
	auto result = ArchiveEventV1{
		.companyIdentityId = companyIdentityId,
		.telegramAccountId = telegramAccountId,
		.peerId = BarePeerId(item->history()->peer->id),
		.messageId = QString::number(item->id.bare),
		.senderId = BarePeerId(item->from()->id),
		.kind = kind,
		.revision = revision,
		.outgoing = item->out(),
		.occurredAt = (kind == ArchiveEventKind::New)
			? QDateTime::fromSecsSinceEpoch(item->date(), Qt::UTC)
			: now,
		.text = item->originalText().text,
		.replyToMessageId = item->replyToId()
			? QString::number(item->replyToId().bare)
			: QString(),
		.forwardedFromId = forwarded
			? BarePeerId(forwarded->id)
			: QString(),
	};
	if (kind == ArchiveEventKind::Delete) {
		result.deletedAt = now;
	}
	if (const auto media = item->media()) {
		if (const auto document = media->document()) {
			result.mediaType = document->mimeString();
			result.mediaName = document->filename();
			result.mediaSize = document->size;
		} else if (media->photo()) {
			result.mediaType = u"image"_q;
		}
	}
	result.eventId = DeterministicEventId(result);
	return result;
}

void Archive(const HistoryItem *item, ArchiveEventKind kind) {
	if (!item || !IsServerMsgId(item->id)) {
		return;
	}
	auto &state = Current();
	auto companyIdentityId = QString();
	auto telegramAccountId = QString();
	auto sink = ArchiveSink();
	auto revision = 0;
	{
		const auto lock = QMutexLocker(&state.mutex);
		if (!state.sink
			|| state.companyIdentityId.isEmpty()
			|| state.telegramAccountId.isEmpty()) {
			return;
		}
		companyIdentityId = state.companyIdentityId;
		telegramAccountId = state.telegramAccountId;
		sink = state.sink;
		const auto key = MessageKey(telegramAccountId, item);
		auto &storedRevision = state.revisions[key];
		if (kind == ArchiveEventKind::Edit) {
			const auto edited = item->Get<HistoryMessageEdited>();
			const auto serverRevision = edited ? edited->date : 0;
			storedRevision = (serverRevision > storedRevision)
				? serverRevision
				: storedRevision + 1;
		}
		revision = storedRevision;
		if (kind == ArchiveEventKind::Delete) {
			state.revisions.remove(key);
		}
	}
	sink(BuildEvent(
		item,
		kind,
		revision,
		companyIdentityId,
		telegramAccountId));
}

} // namespace

void ConfigureArchive(
		QString companyIdentityId,
		QString telegramAccountId,
		ArchiveSink sink) {
	auto &state = Current();
	const auto lock = QMutexLocker(&state.mutex);
	state.companyIdentityId = std::move(companyIdentityId);
	state.telegramAccountId = std::move(telegramAccountId);
	state.sink = std::move(sink);
	state.revisions.clear();
}

void ClearArchive() {
	auto &state = Current();
	const auto lock = QMutexLocker(&state.mutex);
	state.companyIdentityId.clear();
	state.telegramAccountId.clear();
	state.sink = {};
	state.policy = {};
	state.revisions.clear();
}

void ApplyPolicy(PolicyV1 policy) {
	auto &state = Current();
	const auto lock = QMutexLocker(&state.mutex);
	if (policy.version >= state.policy.version) {
		state.policy = std::move(policy);
	}
}

bool ShouldHide(const HistoryItem *item) {
	if (!item) {
		return false;
	}
	auto &state = Current();
	const auto lock = QMutexLocker(&state.mutex);
	return HiddenPeer(state.policy, item->history()->peer)
		|| HiddenPeer(state.policy, item->from())
		|| HiddenPeer(state.policy, item->originalSender());
}

void ArchiveNew(const HistoryItem *item) {
	Archive(item, ArchiveEventKind::New);
}

void ArchiveEdit(const HistoryItem *item) {
	Archive(item, ArchiveEventKind::Edit);
}

void ArchiveDelete(const HistoryItem *item) {
	Archive(item, ArchiveEventKind::Delete);
}

} // namespace Enterprise
