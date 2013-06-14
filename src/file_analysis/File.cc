// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <openssl/md5.h>

#include "File.h"
#include "FileTimer.h"
#include "FileID.h"
#include "Analyzer.h"
#include "Manager.h"
#include "Reporter.h"
#include "Val.h"
#include "Type.h"
#include "Event.h"

#include "analyzer/Analyzer.h"
#include "analyzer/Manager.h"

using namespace file_analysis;

static Val* empty_connection_table()
	{
	TypeList* tbl_index = new TypeList(conn_id);
	tbl_index->Append(conn_id->Ref());
	TableType* tbl_type = new TableType(tbl_index, connection_type->Ref());
	Val* rval = new TableVal(tbl_type);
	Unref(tbl_type);
	return rval;
	}

static RecordVal* get_conn_id_val(const Connection* conn)
	{
	RecordVal* v = new RecordVal(conn_id);
	v->Assign(0, new AddrVal(conn->OrigAddr()));
	v->Assign(1, new PortVal(ntohs(conn->OrigPort()), conn->ConnTransport()));
	v->Assign(2, new AddrVal(conn->RespAddr()));
	v->Assign(3, new PortVal(ntohs(conn->RespPort()), conn->ConnTransport()));
	return v;
	}

int File::id_idx = -1;
int File::parent_id_idx = -1;
int File::source_idx = -1;
int File::is_orig_idx = -1;
int File::conns_idx = -1;
int File::last_active_idx = -1;
int File::seen_bytes_idx = -1;
int File::total_bytes_idx = -1;
int File::missing_bytes_idx = -1;
int File::overflow_bytes_idx = -1;
int File::timeout_interval_idx = -1;
int File::bof_buffer_size_idx = -1;
int File::bof_buffer_idx = -1;
int File::mime_type_idx = -1;

string File::salt;

void File::StaticInit()
	{
	if ( id_idx != -1 )
		return;

	id_idx = Idx("id");
	parent_id_idx = Idx("parent_id");
	source_idx = Idx("source");
	is_orig_idx = Idx("is_orig");
	conns_idx = Idx("conns");
	last_active_idx = Idx("last_active");
	seen_bytes_idx = Idx("seen_bytes");
	total_bytes_idx = Idx("total_bytes");
	missing_bytes_idx = Idx("missing_bytes");
	overflow_bytes_idx = Idx("overflow_bytes");
	timeout_interval_idx = Idx("timeout_interval");
	bof_buffer_size_idx = Idx("bof_buffer_size");
	bof_buffer_idx = Idx("bof_buffer");
	mime_type_idx = Idx("mime_type");

	salt = BifConst::FileAnalysis::salt->CheckString();
	}

File::File(const string& unique, Connection* conn, analyzer::Tag tag,
           bool is_orig)
	: id(""), unique(unique), val(0), postpone_timeout(false),
		first_chunk(true), missed_bof(false), need_reassembly(false), done(false),
		analyzers(this)
	{
	StaticInit();

	char tmp[20];
	uint64 hash[2];
	string msg(unique + salt);
	MD5(reinterpret_cast<const u_char*>(msg.data()), msg.size(),
	    reinterpret_cast<u_char*>(hash));
	uitoa_n(hash[0], tmp, sizeof(tmp), 62);

	DBG_LOG(DBG_FILE_ANALYSIS, "Creating new File object %s (%s)", tmp,
	        unique.c_str());

	val = new RecordVal(fa_file_type);
	val->Assign(id_idx, new StringVal(tmp));
	id = FileID(tmp);

	if ( conn )
		{
		// add source, connection, is_orig fields
		val->Assign(source_idx, new StringVal(analyzer_mgr->GetAnalyzerName(tag)));
		val->Assign(is_orig_idx, new Val(is_orig, TYPE_BOOL));
		UpdateConnectionFields(conn);
		}
	else
		// use the unique file handle as source
		val->Assign(source_idx, new StringVal(unique.c_str()));

	UpdateLastActivityTime();
	}

File::~File()
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "Destroying File object %s", id.c_str());
	Unref(val);
	}

void File::UpdateLastActivityTime()
	{
	val->Assign(last_active_idx, new Val(network_time, TYPE_TIME));
	}

double File::GetLastActivityTime() const
	{
	return val->Lookup(last_active_idx)->AsTime();
	}

void File::UpdateConnectionFields(Connection* conn)
	{
	if ( ! conn )
		return;

	Val* conns = val->Lookup(conns_idx);

	bool is_first = false;

	if ( ! conns )
		{
		is_first = true;
		conns = empty_connection_table();
		val->Assign(conns_idx, conns);
		}

	Val* idx = get_conn_id_val(conn);
	if ( ! conns->AsTableVal()->Lookup(idx) )
		{
		Val* conn_val = conn->BuildConnVal();
		conns->AsTableVal()->Assign(idx, conn_val);

		if ( ! is_first && FileEventAvailable(file_over_new_connection) )
			{
			val_list* vl = new val_list();
			vl->append(val->Ref());
			vl->append(conn_val->Ref());
			FileEvent(file_over_new_connection, vl);
			}
		}

	Unref(idx);
	}

uint64 File::LookupFieldDefaultCount(int idx) const
	{
	Val* v = val->LookupWithDefault(idx);
	uint64 rval = v->AsCount();
	Unref(v);
	return rval;
	}

double File::LookupFieldDefaultInterval(int idx) const
	{
	Val* v = val->LookupWithDefault(idx);
	double rval = v->AsInterval();
	Unref(v);
	return rval;
	}

int File::Idx(const string& field)
	{
	int rval = fa_file_type->FieldOffset(field.c_str());
	if ( rval < 0 )
		reporter->InternalError("Unknown fa_file field: %s", field.c_str());

	return rval;
	}

double File::GetTimeoutInterval() const
	{
	return LookupFieldDefaultInterval(timeout_interval_idx);
	}

void File::SetTimeoutInterval(double interval)
	{
	val->Assign(timeout_interval_idx, new Val(interval, TYPE_INTERVAL));
	}

void File::IncrementByteCount(uint64 size, int field_idx)
	{
	uint64 old = LookupFieldDefaultCount(field_idx);
	val->Assign(field_idx, new Val(old + size, TYPE_COUNT));
	}

void File::SetTotalBytes(uint64 size)
	{
	val->Assign(total_bytes_idx, new Val(size, TYPE_COUNT));
	}

bool File::IsComplete() const
	{
	Val* total = val->Lookup(total_bytes_idx);
	if ( ! total )
		return false;

	if ( LookupFieldDefaultCount(seen_bytes_idx) >= total->AsCount() )
		return true;

	return false;
	}

void File::ScheduleInactivityTimer() const
	{
	timer_mgr->Add(new FileTimer(network_time, id, GetTimeoutInterval()));
	}

bool File::AddAnalyzer(RecordVal* args)
	{
	return done ? false : analyzers.QueueAdd(args);
	}

bool File::RemoveAnalyzer(const RecordVal* args)
	{
	return done ? false : analyzers.QueueRemove(args);
	}

bool File::BufferBOF(const u_char* data, uint64 len)
	{
	if ( bof_buffer.full || bof_buffer.replayed )
		return false;

	uint64 desired_size = LookupFieldDefaultCount(bof_buffer_size_idx);

	bof_buffer.chunks.push_back(new BroString(data, len, 0));
	bof_buffer.size += len;

	if ( bof_buffer.size >= desired_size )
		{
		bof_buffer.full = true;
		ReplayBOF();
		}

	return true;
	}

bool File::DetectMIME(const u_char* data, uint64 len)
	{
	const char* mime = bro_magic_buffer(magic_mime_cookie, data, len);

	if ( mime )
		{
		const char* mime_end = strchr(mime, ';');

		if ( mime_end )
			// strip off charset
			val->Assign(mime_type_idx, new StringVal(mime_end - mime, mime));
		else
			val->Assign(mime_type_idx, new StringVal(mime));
		}

	return mime;
	}

void File::ReplayBOF()
	{
	if ( bof_buffer.replayed )
		return;

	bof_buffer.replayed = true;

	if ( bof_buffer.chunks.empty() )
		{
		// Since we missed the beginning, try file type detect on next data in.
		missed_bof = true;
		return;
		}

	BroString* bs = concatenate(bof_buffer.chunks);
	val->Assign(bof_buffer_idx, new StringVal(bs));

	DetectMIME(bs->Bytes(), bs->Len());

	FileEvent(file_new);

	for ( size_t i = 0; i < bof_buffer.chunks.size(); ++i )
		DataIn(bof_buffer.chunks[i]->Bytes(), bof_buffer.chunks[i]->Len());
	}

void File::DataIn(const u_char* data, uint64 len, uint64 offset)
	{
	analyzers.DrainModifications();

	if ( first_chunk )
		{
		// TODO: this should all really be delayed until we attempt reassembly
		DetectMIME(data, len);
		FileEvent(file_new);
		first_chunk = false;
		}

	file_analysis::Analyzer* a = 0;
	IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		if ( ! a->DeliverChunk(data, len, offset) )
			analyzers.QueueRemove(a->Args());
		}

	analyzers.DrainModifications();

	// TODO: check reassembly requirement based on buffer size in record
	if ( need_reassembly )
		reporter->InternalError("file_analyzer::File TODO: reassembly not yet supported");

	// TODO: reassembly overflow stuff, increment overflow count, eval trigger

	IncrementByteCount(len, seen_bytes_idx);
	}

void File::DataIn(const u_char* data, uint64 len)
	{
	analyzers.DrainModifications();

	if ( BufferBOF(data, len) )
		return;

	if ( missed_bof )
		{
		DetectMIME(data, len);
		FileEvent(file_new);
		missed_bof = false;
		}

	file_analysis::Analyzer* a = 0;
	IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		if ( ! a->DeliverStream(data, len) )
			{
			analyzers.QueueRemove(a->Args());
			continue;
			}

		uint64 offset = LookupFieldDefaultCount(seen_bytes_idx) +
		                LookupFieldDefaultCount(missing_bytes_idx);

		if ( ! a->DeliverChunk(data, len, offset) )
			analyzers.QueueRemove(a->Args());
		}

	analyzers.DrainModifications();
	IncrementByteCount(len, seen_bytes_idx);
	}

void File::EndOfFile()
	{
	if ( done )
		return;

	analyzers.DrainModifications();

	// Send along anything that's been buffered, but never flushed.
	ReplayBOF();

	done = true;

	file_analysis::Analyzer* a = 0;
	IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		if ( ! a->EndOfFile() )
			analyzers.QueueRemove(a->Args());
		}

	FileEvent(file_state_remove);

	analyzers.DrainModifications();
	}

void File::Gap(uint64 offset, uint64 len)
	{
	analyzers.DrainModifications();

	// If we were buffering the beginning of the file, a gap means we've got
	// as much contiguous stuff at the beginning as possible, so work with that.
	ReplayBOF();

	file_analysis::Analyzer* a = 0;
	IterCookie* c = analyzers.InitForIteration();

	while ( (a = analyzers.NextEntry(c)) )
		{
		if ( ! a->Undelivered(offset, len) )
			analyzers.QueueRemove(a->Args());
		}

	if ( FileEventAvailable(file_gap) )
		{
		val_list* vl = new val_list();
		vl->append(val->Ref());
		vl->append(new Val(offset, TYPE_COUNT));
		vl->append(new Val(len, TYPE_COUNT));
		FileEvent(file_gap, vl);
		}

	analyzers.DrainModifications();
	IncrementByteCount(len, missing_bytes_idx);
	}

bool File::FileEventAvailable(EventHandlerPtr h)
	{
	return h && ! file_mgr->IsIgnored(unique);
	}

void File::FileEvent(EventHandlerPtr h)
	{
	if ( ! FileEventAvailable(h) )
		return;

	val_list* vl = new val_list();
	vl->append(val->Ref());
	FileEvent(h, vl);
	}

void File::FileEvent(EventHandlerPtr h, val_list* vl)
	{
	mgr.QueueEvent(h, vl);

	if ( h == file_new || h == file_timeout )
		{
		// immediate feedback is required for these events.
		mgr.Drain();
		analyzers.DrainModifications();
		}
	}
