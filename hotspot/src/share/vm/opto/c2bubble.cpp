/*
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#include "opto/c2bubble.hpp"
#include "runtime/mutexLocker.hpp"
#include "asm/codeBuffer.hpp"
#include "code/debugInfoRec.hpp"
#include "code/nmethod.hpp"
#include "compiler/abstractCompiler.hpp"
#include <math.h>

static void append_to_buf(ChunkBuffer* buf, void* snippet, int sz)
{
  if (sz == 0) return;

  if (buf->capacity < (buf->len + sz)) {
    buf->capacity = (buf->capacity < DEFAULT_CHUNK_SIZE) ? DEFAULT_CHUNK_SIZE : buf->capacity;
    while (buf->capacity < (buf->len + sz)) {
      buf->capacity *= 2;
    }
    buf->hdr = (char*)realloc(buf->hdr, buf->capacity);
    assert(buf->hdr, "malloc");
    buf->ptr = buf->hdr + buf->len;
  }
  memcpy(buf->ptr, snippet, sz);
  buf->ptr += sz;
  buf->len += sz;
  return;
}

void c2b_dump_jit_to_binary(ciMethod* cmethod,
                                   methodHandle method,
                                   int compile_id,              
                                   int entry_bci,               
                                   CodeOffsets* offsets,        
                                   int orig_pc_offset,          
                                   DebugInformationRecorder* debug_info,
                                   Dependencies* dependencies,  
                                   CodeBuffer* code_buffer, int frame_size,
                                   OopMapSet* oop_maps,         
                                   ExceptionHandlerTable* handler_table,
                                   ImplicitExceptionTable* nul_chk_table,
                                   AbstractCompiler* compiler,
                                   int comp_level,
                                   int* size_cb,
                                   int* size_breakdown,
                                   bool has_unsafe_access,
                                   bool has_wide_vectors,
                                   address insts_begin,
                                   int insts_size)
{
  // Calculate the total size requirement for this method dump 
  int sz = 0;
  Thread* thread = Thread::current();
  char str_buf[1024];
  ChunkBuffer chunk;

  method()->name_and_sig_as_C_dotted_string(str_buf, 1024);
  sz += 2;                                              // tag: method_name space_size
  sz += 2;                                              // tag: method_name length
  sz += PAD_BY_4B(strlen(&(str_buf[0]))+1);             // method_name
  sz += 4;                                              // compile_id
  sz += 4;                                              // entry_bci
  sz += 4*CodeOffsets::max_Entries;                     // CodeOffsets 2*8
  sz += 4;                                              // orig_pc_offset
  sz += 4;                                              // tag: DebugInformationRecorder::scopes_data space_size
  sz += 4;                                              // tag: DebugInformationRecorder::scopes_data length 
  sz += PAD_BY_4B(debug_info->stream()->position());    // DebugInformationRecorder::scopes_data
  sz += 2;                                              // tag: PcDesc count
  sz += 4*4*debug_info->_pcs_length;                    // DebugInformationRecorder::scopes_pcs
  sz += 8;                                              // Dependencies::size_in_bytes
  sz += 4;                                              // tag: Dependencies::content_bytes space_size
  sz += PAD_BY_4B(dependencies->size_in_bytes());       // Dependencies::content_bytes
  sz += 4;                                              // CodeBuffer::total_relocation_size
  sz += 4;                                              // CodeBuffer::total_offset_of_insts
  sz += 4;                                              // CodeBuffer::total_offset_of_consts
  sz += 4;                                              // CodeBuffer::total_offset_of_stubs
  sz += 4;                                              // CodeBuffer::total_content_size
  assert(code_buffer->before_expand() == NULL, "before_expand not supported");
  sz += 8*3;                                            // CodeBuffer::_consts::_start/_end/_limit
  sz += 4;                                              // tag CodeBuffer::_consts::_start_end space_size
  sz += 4;                                              // tag CodeBuffer::_consts::_start_end length
  sz += PAD_BY_4B((int)((size_t)code_buffer->_consts._end-(size_t)code_buffer->_consts._start));
                                                        // CodeBuffer::_consts::_start_end
  sz += 4;                                              // tag CodeBuffer::_consts::_locs_start_locs_end space_size
  sz += 4;                                              // tag CodeBuffer::_consts::_locs_start_locs_end length
  sz += PAD_BY_4B((int)((size_t)code_buffer->_consts._locs_end-(size_t)code_buffer->_consts._locs_start));
                                                        // CodeBuffer::_consts::_locs_start_locs_end
  sz += 4;                                              // CodeBuffer::_consts::locs_point_off
  sz += 1;                                              // CodeBuffer::_consts::_frozen
  sz += 1;                                              // CodeBuffer::_consts::_index

  sz += 8*3;                                            // CodeBuffer::_insts::_start/_end/_limit
  sz += 4;                                              // tag CodeBuffer::_insts::_start_end space_size
  sz += 4;                                              // tag CodeBuffer::_insts::_start_end length
  sz += PAD_BY_4B((int)((size_t)code_buffer->_insts._end-(size_t)code_buffer->_insts._start));
                                                        // CodeBuffer::_insts::_start_end
  sz += 4;                                              // tag CodeBuffer::_insts::_locs_start_locs_end space_size
  sz += 4;                                              // tag CodeBuffer::_insts::_locs_start_locs_end length
  sz += PAD_BY_4B((int)((size_t)code_buffer->_insts._locs_end-(size_t)code_buffer->_insts._locs_start));
                                                        // CodeBuffer::_insts::_locs_start_locs_end
  sz += 4;                                              // CodeBuffer::_insts::locs_point_off
  sz += 1;                                              // CodeBuffer::_insts::_frozen
  sz += 1;                                              // CodeBuffer::_insts::_index

  sz += 8*3;                                            // CodeBuffer::_stubs::_start/_end/_limit
  sz += 4;                                              // tag CodeBuffer::_stubs::_start_end space_size
  sz += 4;                                              // tag CodeBuffer::_stubs::_start_end length
  sz += PAD_BY_4B((int)((size_t)code_buffer->_stubs._end-(size_t)code_buffer->_stubs._start));
                                                        // CodeBuffer::_stubs::_start_end
  sz += 4;                                              // tag CodeBuffer::_stubs::_locs_start_locs_end space_size
  sz += 4;                                              // tag CodeBuffer::_stubs::_locs_start_locs_end length
  sz += PAD_BY_4B((int)((size_t)code_buffer->_stubs._locs_end-(size_t)code_buffer->_stubs._locs_start));
                                                        // CodeBuffer::_stubs::_locs_start_locs_end
  sz += 4;                                              // CodeBuffer::_stubs::locs_point_off
  sz += 1;                                              // CodeBuffer::_stubs::_frozen
  sz += 1;                                              // CodeBuffer::_stubs::_index


  sz += 1;                                              // OopRecorder::is_unused
  sz += 1;                                              // OopRecorder::_oops::is_unused
  if (!code_buffer->oop_recorder()->_oops.is_unused()) {
    sz += 2;                                            // OopRecorder::_oops::length
    sz += 8*code_buffer->oop_recorder()->_oops._handles->length();
                                                        // OopRecorder::_oops::_handles
  }
  sz += 1;                                              // OopRecorder::_metadata::is_unused
  if (!code_buffer->oop_recorder()->_metadata.is_unused()) {
    sz += 2;                                            // OopRecorder::_metadata::length
    sz += 8*code_buffer->oop_recorder()->_metadata._handles->length();
                                                        // OopRecorder::_metadata::_handles
  }

  sz += 4;                                              // frame_size
  sz += 1;                                              // tag OopMapSet exists
  if (oop_maps) {
    sz += 3*4;                                            // OopMapSet::heap_size/_om_count/_om_size
    for (int i = 0; i < oop_maps->_om_count; i++) {
      sz += 4*4;                                        // OopMapSet::_om_heap_size/_om_count/_om_size
      sz += 4;                                          // tag OopMapSet::_om_data::_omv_data space_size
      sz += 4;                                          // tag OopMapSet::_om_data::_omv_data length
      sz += PAD_BY_4B((int)oop_maps->at(i)->write_stream()->position());
                                                        // OopMapSet::_om_data::_omv_data
    }
  }

  sz += 4;                                              // ExceptionHandlerTable::size_in_bytes
  sz += 4;                                              // tag ExceptionHandlerTable::_table space_size
  sz += 4;                                              // tag ExceptionHandlerTable::_table length
  sz += PAD_BY_4B((int)handler_table->size_in_bytes()); // ExceptionHandlerTable::_table

  sz += 4;                                              // ImplicitExceptionTable::size_in_bytes
  sz += 4;                                              // tag ImplicitExceptionTable::_data space_size
  sz += 4;                                              // tag ImplicitExceptionTable::_data length
  sz += PAD_BY_4B((int)(2*nul_chk_table->len()*sizeof(implicit_null_entry)));
                                                        // ImplicitExceptionTable::_data
  sz += 4;                                              // ImplicitExceptionTable::_len

  sz += 2;                                              // comp_level
  sz += 4;                                              // nmethod::allocation_size
  sz += 8;                                              // DebugInformationRecorder::pcs_size/data_size
  sz += 8;                                              // CodeBuffer::total_oop_size/total_metadata_size

  sz += 2;                                              // has_unsafe_access/has_wide_vectors

  // Get memory and do the dump
  if (thread->_jit_dump_buffer_sz == 0) {
    thread->_jit_dump_buffer_sz = 160*1024;	// largest size so far is 139350
    thread->_jit_dump_buffer = (unsigned char*)calloc(thread->_jit_dump_buffer_sz, 1);
    assert(thread->_jit_dump_buffer != NULL, "malloc");
  }
  if (thread->_jit_dump_buffer_sz < (int)(sz+2*sizeof(unsigned int)+sizeof(unsigned long))) {
    while (thread->_jit_dump_buffer_sz < (int)(sz+2*sizeof(unsigned int)+sizeof(unsigned long))) {
      thread->_jit_dump_buffer_sz *= 2;
    }
    free(thread->_jit_dump_buffer);
    thread->_jit_dump_buffer = (unsigned char*)calloc(thread->_jit_dump_buffer_sz, 1);
    assert(thread->_jit_dump_buffer != NULL, "malloc");
  }

  // dump into file
  unsigned char* buf = thread->_jit_dump_buffer;
  unsigned char* uchar_ptr = NULL;
  unsigned short* ushort_ptr = NULL;
  unsigned int* uint_ptr = NULL;
  unsigned long* ulong_ptr = NULL;
  char* char_ptr = NULL;
  short* short_ptr = NULL;
  int* int_ptr = NULL;
  long* long_ptr = NULL;
  unsigned char* ptr_chunk_start = NULL;
  //jitlog("C2B dump Method:%s\n", str_buf);

  memset(buf, 0, (sz+2*sizeof(unsigned int)+sizeof(unsigned long)));
  memset((void*)&chunk, 0, sizeof(ChunkBuffer));
  // Leave space for the "JITB" magic
  buf += 1*sizeof(unsigned int);
  // Leave space for method hash
  buf += 1*sizeof(unsigned long);
  // Leave space for the first int tag
  buf += 1*sizeof(unsigned int);
  ushort_ptr = (unsigned short*)buf;
  ushort_ptr[0] = (unsigned short)PAD_BY_4B(strlen(&(str_buf[0]))+1);        // tag: method_name space_size
  ushort_ptr[1] = (unsigned short)(strlen(&(str_buf[0]))+1);                     // tag: method_name length
  buf += 2*sizeof(unsigned short);
  memcpy((void*)buf, (void*)&(str_buf[0]), strlen(&(str_buf[0]))+1);        // method_name
  buf += ushort_ptr[0];
  int_ptr = (int*)buf;
  int_ptr[0] = compile_id;                                // compile_id
  int_ptr[1] = entry_bci;                                 // entry_bci
  append_to_buf(&chunk, (char*)&(entry_bci), sizeof(int));
  for (int i = 0; i < CodeOffsets::max_Entries; i++) {                      // CodeOffsets 2*8
    int_ptr[2+i] = offsets->_values[i];
  }
  append_to_buf(&chunk, (char*)&(int_ptr[2]), CodeOffsets::max_Entries*sizeof(int));
  buf += (2+CodeOffsets::max_Entries)*sizeof(int);

  int_ptr = (int*)buf;
  int_ptr[0] = orig_pc_offset;                            // orig_pc_offset
  append_to_buf(&chunk, (char*)&orig_pc_offset, sizeof(int));
  int_ptr[1] = PAD_BY_4B(debug_info->stream()->position());   // tag: DebugInformationRecorder::scopes_data space_size
  int_ptr[2] = debug_info->stream()->position();          // tag: DebugInformationRecorder::scopes_data length 
  buf += 3*sizeof(int);
  memcpy((void*)buf, (void*)debug_info->stream()->buffer(), int_ptr[2]);  // DebugInformationRecorder::scopes_data
  append_to_buf(&chunk, buf, int_ptr[2]);
  buf += int_ptr[1];

  ushort_ptr = (unsigned short*)buf;
  ushort_ptr[0] = (unsigned short)debug_info->_pcs_length;                   // tag: PcDesc count
  append_to_buf(&chunk, (char*)&(debug_info->_pcs_length), sizeof(unsigned short));
  buf += 1*sizeof(unsigned short);
  PcDesc* pc_ptr = debug_info->_pcs;
  ptr_chunk_start = buf;
  for (int i = 0; i < debug_info->_pcs_length; i++) {                       // DebugInformationRecorder::scopes_pcs
    int_ptr = (int*)buf;
    int_ptr[0] = pc_ptr->_pc_offset;
    int_ptr[1] = pc_ptr->_scope_decode_offset;
    int_ptr[2] = pc_ptr->_obj_decode_offset;
    int_ptr[3] = pc_ptr->_flags;
    pc_ptr++;
    buf += 4*sizeof(int);
  }
  append_to_buf(&chunk, ptr_chunk_start, debug_info->_pcs_length*4*sizeof(int));

  ulong_ptr = (unsigned long*)buf;
  ulong_ptr[0] = dependencies->size_in_bytes();                              // Dependencies::size_in_bytes
  buf += 1*sizeof(unsigned long);
  int_ptr = (int*)buf;
  int_ptr[0] = PAD_BY_4B(dependencies->size_in_bytes());                  // tag: Dependencies::content_bytes space_size
  buf += 1*sizeof(int);
  memcpy((void*)buf, (void*)dependencies->content_bytes(), ulong_ptr[0]);    // Dependencies::content_bytes
  append_to_buf(&chunk, buf, ulong_ptr[0]);
  buf += int_ptr[0];

  int_ptr = (int*)buf;
  int_ptr[0] = code_buffer->total_relocation_size();                        // CodeBuffer::total_relocation_size
  int_ptr[1] = code_buffer->total_offset_of(code_buffer->insts());          // CodeBuffer::total_offset_of_insts
  int_ptr[2] = code_buffer->total_offset_of(code_buffer->consts());         // CodeBuffer::total_offset_of_consts
  int_ptr[3] = code_buffer->total_offset_of(code_buffer->stubs());          // CodeBuffer::total_offset_of_stubs
  int_ptr[4] = code_buffer->total_content_size();                           // CodeBuffer::total_content_size
  append_to_buf(&chunk, buf, 5*sizeof(int));
  buf += 5*sizeof(int);

  ulong_ptr = (unsigned long*)buf;
  ulong_ptr[0] = (unsigned long)code_buffer->_consts._start;                                // CodeBuffer::_consts::_start/_end/_limit
  ulong_ptr[1] = (unsigned long)code_buffer->_consts._end;
  ulong_ptr[2] = (unsigned long)code_buffer->_consts._limit;
  buf += 3*sizeof(unsigned long);

  int_ptr = (int*)buf;
  int_ptr[0] = PAD_BY_4B((int)((size_t)code_buffer->_consts._end-(size_t)code_buffer->_consts._start));   // tag CodeBuffer::_consts::_start_end space_size
  int_ptr[1] = (int)((size_t)code_buffer->_consts._end-(size_t)code_buffer->_consts._start);    // tag CodeBuffer::_consts::_start_end length
  buf += 2*sizeof(int);
  memcpy((void*)buf, (void*)code_buffer->_consts._start, (int)((size_t)code_buffer->_consts._end-(size_t)code_buffer->_consts._start));             // CodeBuffer::_consts::_start_end
  buf += int_ptr[0];

  int_ptr = (int*)buf;
  int_ptr[0] = PAD_BY_4B((int)((size_t)code_buffer->_consts._locs_end-(size_t)code_buffer->_consts._locs_start)); // tag CodeBuffer::_consts::_locs_start_locs_end space_size
  int_ptr[1] = (int)((size_t)code_buffer->_consts._locs_end-(size_t)code_buffer->_consts._locs_start); // tag CodeBuffer::_consts::_locs_start_locs_end length
  buf += 2*sizeof(int);
  memcpy((void*)buf, (void*)code_buffer->_consts._locs_start, (int)((size_t)code_buffer->_consts._locs_end-(size_t)code_buffer->_consts._locs_start));          // CodeBuffer::_consts::_locs_start_locs_end
  buf += int_ptr[0];

  int_ptr = (int*)buf;
  int_ptr[0] = code_buffer->_consts.locs_point_off();                           // CodeBuffer::_consts::locs_point_off
  buf += 1*sizeof(int);

  uchar_ptr = (unsigned char*)buf;
  uchar_ptr[0] = code_buffer->_consts._frozen;                                   // CodeBuffer::_consts::_frozen
  uchar_ptr[1] = (unsigned char)code_buffer->_consts._index;                     // CodeBuffer::_consts::_index
  buf += 2*sizeof(unsigned char);

  ulong_ptr = (unsigned long*)buf;
  ulong_ptr[0] = (unsigned long)code_buffer->_insts._start;                                // CodeBuffer::_insts::_start/_end/_limit
  ulong_ptr[1] = (unsigned long)code_buffer->_insts._end;
  ulong_ptr[2] = (unsigned long)code_buffer->_insts._limit;
  buf += 3*sizeof(unsigned long);

  int_ptr = (int*)buf;
  int_ptr[0] = PAD_BY_4B((int)((size_t)code_buffer->_insts._end-(size_t)code_buffer->_insts._start));   // tag CodeBuffer::_insts::_start_end space_size
  int_ptr[1] = (int)((size_t)code_buffer->_insts._end-(size_t)code_buffer->_insts._start);    // tag CodeBuffer::_insts::_start_end length
  buf += 2*sizeof(int);
  memcpy((void*)buf, (void*)code_buffer->_insts._start, (int)((size_t)code_buffer->_insts._end-(size_t)code_buffer->_insts._start));             // CodeBuffer::_insts::_start_end
  buf += int_ptr[0];

  int_ptr = (int*)buf;
  int_ptr[0] = PAD_BY_4B((int)((size_t)code_buffer->_insts._locs_end-(size_t)code_buffer->_insts._locs_start)); // tag CodeBuffer::_insts::_locs_start_locs_end space_size
  int_ptr[1] = (int)((size_t)code_buffer->_insts._locs_end-(size_t)code_buffer->_insts._locs_start); // tag CodeBuffer::_insts::_locs_start_locs_end length
  buf += 2*sizeof(int);
  memcpy((void*)buf, (void*)code_buffer->_insts._locs_start, (int)((size_t)code_buffer->_insts._locs_end-(size_t)code_buffer->_insts._locs_start));          // CodeBuffer::_insts::_locs_start_locs_end
  buf += int_ptr[0];

  int_ptr = (int*)buf;
  int_ptr[0] = code_buffer->_insts.locs_point_off();                           // CodeBuffer::_insts::locs_point_off
  buf += 1*sizeof(int);

  uchar_ptr = (unsigned char*)buf;
  uchar_ptr[0] = code_buffer->_insts._frozen;                                   // CodeBuffer::_insts::_frozen
  uchar_ptr[1] = (unsigned char)code_buffer->_insts._index;                     // CodeBuffer::_insts::_index
  buf += 2*sizeof(unsigned char);

  ulong_ptr = (unsigned long*)buf;
  ulong_ptr[0] = (unsigned long)code_buffer->_stubs._start;                                // CodeBuffer::_stubs::_start/_end/_limit
  ulong_ptr[1] = (unsigned long)code_buffer->_stubs._end;
  ulong_ptr[2] = (unsigned long)code_buffer->_stubs._limit;
  buf += 3*sizeof(unsigned long);

  int_ptr = (int*)buf;
  int_ptr[0] = PAD_BY_4B((int)((size_t)code_buffer->_stubs._end-(size_t)code_buffer->_stubs._start));   // tag CodeBuffer::_stubs::_start_end space_size
  int_ptr[1] = (int)((size_t)code_buffer->_stubs._end-(size_t)code_buffer->_stubs._start);    // tag CodeBuffer::_stubs::_start_end length
  buf += 2*sizeof(int);
  memcpy((void*)buf, (void*)code_buffer->_stubs._start, (int)((size_t)code_buffer->_stubs._end-(size_t)code_buffer->_stubs._start));             // CodeBuffer::_stubs::_start_end
  buf += int_ptr[0];

  int_ptr = (int*)buf;
  int_ptr[0] = PAD_BY_4B((int)((size_t)code_buffer->_stubs._locs_end-(size_t)code_buffer->_stubs._locs_start)); // tag CodeBuffer::_stubs::_locs_start_locs_end space_size
  int_ptr[1] = (int)((size_t)code_buffer->_stubs._locs_end-(size_t)code_buffer->_stubs._locs_start); // tag CodeBuffer::_stubs::_locs_start_locs_end length
  buf += 2*sizeof(int);
  memcpy((void*)buf, (void*)code_buffer->_stubs._locs_start, (int)((size_t)code_buffer->_stubs._locs_end-(size_t)code_buffer->_stubs._locs_start));          // CodeBuffer::_stubs::_locs_start_locs_end
  buf += int_ptr[0];

  int_ptr = (int*)buf;
  int_ptr[0] = code_buffer->_stubs.locs_point_off();                           // CodeBuffer::_stubs::locs_point_off
  buf += 1*sizeof(int);

  uchar_ptr = (unsigned char*)buf;
  uchar_ptr[0] = code_buffer->_stubs._frozen;                                   // CodeBuffer::_stubs::_frozen
  uchar_ptr[1] = (unsigned char)code_buffer->_stubs._index;                     // CodeBuffer::_stubs::_index
  buf += 2*sizeof(unsigned char);

  uchar_ptr = (unsigned char*)buf;
  uchar_ptr[0] = code_buffer->oop_recorder()->is_unused();                       // OopRecorder::is_unused
  uchar_ptr[1] = code_buffer->oop_recorder()->_oops.is_unused();                 // OopRecorder::_oops::is_unused
  buf += 2*sizeof(unsigned char);
  if (!code_buffer->oop_recorder()->_oops.is_unused()) {
    ushort_ptr = (unsigned short*)buf;
    ushort_ptr[0] = (unsigned short)code_buffer->oop_recorder()->_oops._handles->length();       // OopRecorder::_oops::length
    buf += 1*sizeof(unsigned short);
    ulong_ptr = (unsigned long*)buf;
    Thread* thr = Thread::current();
    for (int i = 0; i < code_buffer->oop_recorder()->_oops._handles->length(); i++) {
      ulong_ptr[i] = (size_t)(code_buffer->oop_recorder()->_oops._handles->at(i));             // OopRecorder::_oops::_handles
    }
    buf += sizeof(unsigned long)*code_buffer->oop_recorder()->_oops._handles->length();
  }

  uchar_ptr = (unsigned char*)buf;
  uchar_ptr[0] = code_buffer->oop_recorder()->_metadata.is_unused();             // OopRecorder::_metadata::is_unused
  buf += 1*sizeof(unsigned char);
  if (!code_buffer->oop_recorder()->_metadata.is_unused()) {
    ushort_ptr = (unsigned short*)buf;
    ushort_ptr[0] = (unsigned short)code_buffer->oop_recorder()->_metadata._handles->length();   // OopRecorder::_metadata::length
    buf += 1*sizeof(unsigned short);
    ulong_ptr = (unsigned long*)buf;
    for (int i = 0; i < code_buffer->oop_recorder()->_metadata._handles->length(); i++) {
      ulong_ptr[i] = (size_t)(code_buffer->oop_recorder()->_metadata._handles->at(i));       // OopRecorder::_metadata::_handles
    }
    buf += sizeof(unsigned long)*code_buffer->oop_recorder()->_metadata._handles->length();
  }

  int_ptr = (int*)buf;
  int_ptr[0] = frame_size;                                                      // frame_size
  append_to_buf(&chunk, (char*)&frame_size, sizeof(int));
  buf += 1*sizeof(int);

  uchar_ptr = (unsigned char*)buf;
  uchar_ptr[0] = oop_maps == NULL ? 0 : 1;                                       // tag OopMapSet exists
  buf += 1*sizeof(unsigned char);
  if (oop_maps) {
    int_ptr = (int*)buf;
    int_ptr[0] = oop_maps->heap_size();                                         // OopMapSet::heap_size/_om_count/_om_size
    int_ptr[1] = oop_maps->_om_count;
    int_ptr[2] = oop_maps->_om_size;
    append_to_buf(&chunk, buf, 3*sizeof(int));
    buf += 3*sizeof(int);
    for (int i = 0; i < oop_maps->_om_count; i++) {
      int_ptr = (int*)buf;
      int_ptr[0] = oop_maps->at(i)->_pc_offset;                                 // OopMapSet::_om_heap_size/_om_count/_om_size
      int_ptr[1] = oop_maps->at(i)->_omv_count;
      int_ptr[2] = oop_maps->at(i)->write_stream()->position();
      buf += 3*sizeof(int);
      int_ptr = (int*)buf;
      int_ptr[0] = PAD_BY_4B((int)oop_maps->at(i)->write_stream()->position());   // tag OopMapSet::_om_data::_omv_data space_size
      int_ptr[1] = oop_maps->at(i)->write_stream()->position();   // tag OopMapSet::_om_data::_omv_data length
      buf += 2*sizeof(int);
      memcpy((void*)buf, (void*)oop_maps->at(i)->write_stream()->buffer(), (int)oop_maps->at(i)->write_stream()->position());           // OopMapSet::_om_data::_omv_data
      buf += int_ptr[0];

      int_ptr = (int*)buf;
      int_ptr[0] = oop_maps->at(i)->heap_size();
      buf += 1*sizeof(int);
    }
    // FIXME: check why OopMapSet could be different even parser get the same dump
  }

  int_ptr = (int*)buf;
  int_ptr[0] = handler_table->size_in_bytes();                                  // ExceptionHandlerTable::size_in_bytes
  buf += 1*sizeof(int);
  int_ptr = (int*)buf;
  int_ptr[0] = PAD_BY_4B((int)handler_table->size_in_bytes());                // tag ExceptionHandlerTable::_table space_size
  int_ptr[1] = handler_table->size_in_bytes();                // tag ExceptionHandlerTable::_table length
  buf += 2*sizeof(int);
  memcpy((void*)buf, (void*)handler_table->_table, (int)handler_table->size_in_bytes());        // ExceptionHandlerTable::_table
  append_to_buf(&chunk, buf, (int)handler_table->size_in_bytes());
  buf += int_ptr[0];

  int_ptr = (int*)buf;
  int_ptr[0] = nul_chk_table->size_in_bytes();                                  // ImplicitExceptionTable::size_in_bytes
  buf += 1*sizeof(int);
  int_ptr = (int*)buf;
  int_ptr[0] = PAD_BY_4B((int)(2*nul_chk_table->len()*sizeof(implicit_null_entry)));          // tag ImplicitExceptionTable::_data space_size
  int_ptr[1] = (2*nul_chk_table->len()*sizeof(implicit_null_entry));          // tag ImplicitExceptionTable::_data length
  buf += 2*sizeof(int);
  memcpy((void*)buf, (void*)nul_chk_table->_data, (int)(2*nul_chk_table->len()*sizeof(implicit_null_entry)));           // ImplicitExceptionTable::_data
  append_to_buf(&chunk, buf, (int)(2*nul_chk_table->len()*sizeof(implicit_null_entry)));
  buf += int_ptr[0];
  int_ptr = (int*)buf;
  int_ptr[0] = nul_chk_table->len();                                            // ImplicitExceptionTable::_len
  buf += 1*sizeof(int);

  ushort_ptr = (unsigned short*)buf;
  ushort_ptr[0] = (unsigned short)comp_level;                                    // comp_level
  append_to_buf(&chunk, (char*)&comp_level, sizeof(unsigned short));
  buf += 1*sizeof(unsigned short);

  int_ptr = (int*)buf;
  int_ptr[0] = size_cb[0];                                                      // nmethod::allocation_size
  int_ptr[1] = size_cb[1];                                                      // DebugInformationRecorder::pcs_size/data_size
  int_ptr[2] = size_cb[2];
  int_ptr[3] = size_cb[3];                                                      // CodeBuffer::total_oop_size/total_metadata_size
  int_ptr[4] = size_cb[4];
  append_to_buf(&chunk, buf, 5*sizeof(int));
  buf += 5*sizeof(int);

  uchar_ptr = (unsigned char*)buf;
  uchar_ptr[0] = has_unsafe_access;
  uchar_ptr[1] = has_wide_vectors;
  append_to_buf(&chunk, buf, 2*sizeof(unsigned char));
  buf += 2*sizeof(unsigned char);

  /* Calculate hash from chunk buffer */
  unsigned long chunk_hash = 5381;
  int idx = 0;
  int c;
  while (idx < chunk.len) {
    c = chunk.hdr[idx];
    chunk_hash = ((chunk_hash << 5) + chunk_hash) + c;
    idx++;
  }
  if (chunk.hdr != NULL) {
    free(chunk.hdr);
  }

  assert((int)(buf-thread->_jit_dump_buffer) == (sz+2*sizeof(unsigned int)+sizeof(unsigned long)), "debug");
  buf = (unsigned char*)thread->_jit_dump_buffer;
  uchar_ptr = (unsigned char*)buf;
  uchar_ptr[0] = 'J';
  uchar_ptr[1] = 'I';
  uchar_ptr[2] = 'T';
  uchar_ptr[3] = 'B';
  buf += 4*sizeof(unsigned char);
  ulong_ptr = (unsigned long*)buf;
  ulong_ptr[0] = chunk_hash;
  buf += 1*sizeof(unsigned long);
  uint_ptr = (unsigned int*)buf;
  uint_ptr[0] = sz;

  if (jit_fd != NULL) {
    size_t ret = fwrite((void*)thread->_jit_dump_buffer, (sz+2*sizeof(unsigned int)+sizeof(unsigned long)), 1, jit_fd);
    assert(ret == 1, "debug");
    fflush(jit_fd);
  }
}

void c2b_nmethod_dump(nmethod* nm)
{
  // Calculate the total size requirement for this method dump 
  int sz = 0;
  Thread* thread = Thread::current();
  char str_buf[1024];
  ChunkBuffer chunk;

  nm->method()->name_and_sig_as_C_dotted_string(str_buf, 1024);
  sz += 2;                                              // tag: method_name space_size
  sz += 2;                                              // tag: method_name length
  sz += PAD_BY_4B(strlen(&(str_buf[0]))+1);             // method_name
  sz += 4;						// _entry_point_offset
  sz += 4;						// _verified_entry_point_offset
  sz += 4*17;						// nmethod int fields
  sz += 4*8;						// codeBlob int fields
  sz += 1;                                              // tag OopMapSet exists
  if (nm->_oop_maps) {
    sz += 2*4;                                            // OopMapSet::_om_count/_om_size
    for (int i = 0; i < nm->_oop_maps->_om_count; i++) {
      sz += 4*3;                                        // OopMap::_pc_offset/_omv_count/_omv_data_size
      sz += 4;                                          // tag OopMapSet::_om_data::_omv_data space_size
      sz += 4;                                          // tag OopMapSet::_om_data::_omv_data length
      sz += PAD_BY_4B((int)nm->_oop_maps->at(i)->_omv_data_size);
                                                        // OopMapSet::_om_data::_omv_data
    }
  }
  sz += 8;						// Inst address
  sz += 4;						// CodeBlob::_size - sizeof(nmethod)
  sz += nm->_size - sizeof(nmethod);

  // Get memory and do the dump
  if (thread->_jit_dump_buffer_sz == 0) {
    thread->_jit_dump_buffer_sz = 160*1024;	// largest size so far is 139350
    thread->_jit_dump_buffer = (unsigned char*)calloc(thread->_jit_dump_buffer_sz, 1);
    assert(thread->_jit_dump_buffer != NULL, "malloc");
  }
  if (thread->_jit_dump_buffer_sz < (int)(sz+2*sizeof(unsigned int)+sizeof(unsigned long))) {
    while (thread->_jit_dump_buffer_sz < (int)(sz+2*sizeof(unsigned int)+sizeof(unsigned long))) {
      thread->_jit_dump_buffer_sz *= 2;
    }
    free(thread->_jit_dump_buffer);
    thread->_jit_dump_buffer = (unsigned char*)calloc(thread->_jit_dump_buffer_sz, 1);
    assert(thread->_jit_dump_buffer != NULL, "malloc");
  }

  // dump into file
  unsigned char* buf = thread->_jit_dump_buffer;
  unsigned char* uchar_ptr = NULL;
  unsigned short* ushort_ptr = NULL;
  unsigned int* uint_ptr = NULL;
  unsigned long* ulong_ptr = NULL;
  char* char_ptr = NULL;
  short* short_ptr = NULL;
  int* int_ptr = NULL;
  long* long_ptr = NULL;
  unsigned char* ptr_chunk_start = NULL;

  memset(buf, 0, (sz+2*sizeof(unsigned int)+sizeof(unsigned long)));
  memset((void*)&chunk, 0, sizeof(ChunkBuffer));
  // Leave space for the "JITB" magic
  buf += 1*sizeof(unsigned int);
  // Leave space for method hash
  buf += 1*sizeof(unsigned long);
  // Leave space for the first int tag
  buf += 1*sizeof(unsigned int);
  ushort_ptr = (unsigned short*)buf;
  ushort_ptr[0] = (unsigned short)PAD_BY_4B(strlen(&(str_buf[0]))+1);        // tag: method_name space_size
  ushort_ptr[1] = (unsigned short)(strlen(&(str_buf[0]))+1);                     // tag: method_name length
  buf += 2*sizeof(unsigned short);
  memcpy((void*)buf, (void*)&(str_buf[0]), strlen(&(str_buf[0]))+1);        // method_name
  buf += ushort_ptr[0];

  int_ptr = (int*)buf;
  int_ptr[0] = (int)(nm->_entry_point - nm->insts_begin());                                // _entry_point_offset
  int_ptr[1] = (int)(nm->_verified_entry_point - nm->insts_begin());                       // _verified_entry_point_offset
  append_to_buf(&chunk, (char*)&(int_ptr[0]), 2*sizeof(int));
  buf += 2*sizeof(int);

  int_ptr = (int*)buf;							// nmethod int fields
  int_ptr[0] = nm->_exception_offset;
  int_ptr[1] = nm->_deoptimize_offset;
  int_ptr[2] = nm->_deoptimize_mh_offset;
  int_ptr[3] = nm->_unwind_handler_offset;
  int_ptr[4] = nm->_consts_offset;
  int_ptr[5] = nm->_stub_offset;
  int_ptr[6] = nm->_oops_offset;
  int_ptr[7] = nm->_metadata_offset;
  int_ptr[8] = nm->_scopes_data_offset;
  int_ptr[9] = nm->_scopes_pcs_offset;
  int_ptr[10] = nm->_dependencies_offset;
  int_ptr[11] = nm->_handler_table_offset;
  int_ptr[12] = nm->_nul_chk_table_offset;
  int_ptr[13] = nm->_nmethod_end_offset;
  int_ptr[14] = nm->_orig_pc_offset;
  int_ptr[15] = nm->_compile_id;
  int_ptr[16] = nm->_comp_level;
  append_to_buf(&chunk, (char*)&(int_ptr[0]), 17*sizeof(int));
  buf += 17*sizeof(int);

  int_ptr = (int*)buf;							// codeBlob int fields
  int_ptr[0] = nm->_size;
  int_ptr[1] = nm->_header_size;
  int_ptr[2] = nm->_relocation_size;
  int_ptr[3] = nm->_content_offset;
  int_ptr[4] = nm->_code_offset;
  int_ptr[5] = nm->_frame_complete_offset;
  int_ptr[6] = nm->_data_offset;
  int_ptr[7] = nm->_frame_size;
  append_to_buf(&chunk, (char*)&(int_ptr[0]), 8*sizeof(int));
  buf += 8*sizeof(int);

  uchar_ptr = (unsigned char*)buf;
  uchar_ptr[0] = nm->_oop_maps == NULL ? 0 : 1;                                       // tag oopmapset exists
  buf += 1*sizeof(unsigned char);
  if (nm->_oop_maps != NULL) {
    int_ptr = (int*)buf;
    int_ptr[0] = nm->_oop_maps->_om_count;
    int_ptr[1] = nm->_oop_maps->_om_size;
    append_to_buf(&chunk, buf, 2*sizeof(int));
    buf += 2*sizeof(int);
    for (int i = 0; i < nm->_oop_maps->_om_count; i++) {
      int_ptr = (int*)buf;
      int_ptr[0] = nm->_oop_maps->at(i)->_pc_offset;                                 // OopMapSet::_om_heap_size/_om_count/_om_size
      int_ptr[1] = nm->_oop_maps->at(i)->_omv_count;
      int_ptr[2] = nm->_oop_maps->at(i)->_omv_data_size;
      append_to_buf(&chunk, buf, 3*sizeof(int));
      buf += 3*sizeof(int);
      int_ptr = (int*)buf;
      int_ptr[0] = PAD_BY_4B((int)nm->_oop_maps->at(i)->_omv_data_size);   // tag OopMapSet::_om_data::_omv_data space_size
      int_ptr[1] = nm->_oop_maps->at(i)->_omv_data_size;   // tag OopMapSet::_om_data::_omv_data length
      append_to_buf(&chunk, buf, 2*sizeof(int));
      buf += 2*sizeof(int);
      memcpy((void*)buf, (void*)nm->_oop_maps->at(i)->_omv_data, (int)nm->_oop_maps->at(i)->_omv_data_size);           // OopMapSet::_om_data::_omv_data
      append_to_buf(&chunk, buf, int_ptr[0]);
      buf += int_ptr[0];
    }
  }
  ulong_ptr = (unsigned long*)buf;						// Insts address
  ulong_ptr[0] = (unsigned long)nm->insts_begin();
  buf += sizeof(unsigned long);
  int_ptr = (int*)buf;								// CodeBlob::_size - sizeof(nmethod)
  int_ptr[0] = nm->_size - sizeof(nmethod);
  append_to_buf(&chunk, buf, sizeof(int));
  buf += 1*sizeof(int);
  memcpy((void*)buf, (void*)(((unsigned long)nm)+sizeof(nmethod)), (nm->_size-sizeof(nmethod)));
  // section before insts+stubs
  append_to_buf(&chunk, buf, (nm->_code_offset-sizeof(nmethod)));
  // section insts
  int i;
  int* ptr = NULL;
  for (i = 0, ptr = (int*)nm->insts_begin(); i < (nm->_stub_offset-nm->_code_offset)/4; i++, ptr++) {
    int cur_inst = *ptr;
    address b_dest_address = NULL;
    // FIXME
    /*
    if (Assembler::is_bxx(cur_inst)) {
      int b_dest = Assembler::inv_li_field(cur_inst) + i*4;
      if (b_dest < 0 || b_dest >= (nm->_stub_offset-nm->_code_offset)) {
        b_dest_address = Assembler::bxx_destination(cur_inst, (address)ptr);
      }
    } else if (Assembler::is_bcxx(cur_inst)) {
      int b_dest = Assembler::inv_bd_field(cur_inst, 0) + i*4;
      if (b_dest < 0 || b_dest >= (nm->_stub_offset-nm->_code_offset)) {
        b_dest_address = (address)((intptr_t)ptr + b_dest);
      }
    }
    */
    if (b_dest_address != NULL) {
      append_to_buf(&chunk, &b_dest_address, sizeof(address));
    } else {
      append_to_buf(&chunk, ptr, sizeof(int));
    }
  }
  // section after insts+stubs
  append_to_buf(&chunk, buf+nm->_oops_offset-sizeof(nmethod), (nm->_size-sizeof(nmethod)-(nm->_code_offset-sizeof(nmethod))-(nm->_oops_offset-nm->_code_offset)));
  buf += (nm->_size-sizeof(nmethod));

  /* Calculate hash from chunk buffer */
  unsigned long chunk_hash = 5381;
  int idx = 0;
  int c;
  while (idx < chunk.len) {
    c = chunk.hdr[idx];
    chunk_hash = ((chunk_hash << 5) + chunk_hash) + c;
    idx++;
  }
  if (chunk.hdr != NULL) {
    free(chunk.hdr);
  }

  assert((int)(buf-thread->_jit_dump_buffer) == (sz+2*sizeof(unsigned int)+sizeof(unsigned long)), "debug");
  buf = (unsigned char*)thread->_jit_dump_buffer;
  uchar_ptr = (unsigned char*)buf;
  uchar_ptr[0] = 'J';
  uchar_ptr[1] = 'I';
  uchar_ptr[2] = 'T';
  uchar_ptr[3] = 'N';
  buf += 4*sizeof(unsigned char);
  ulong_ptr = (unsigned long*)buf;
  ulong_ptr[0] = chunk_hash;
  buf += 1*sizeof(unsigned long);
  uint_ptr = (unsigned int*)buf;
  uint_ptr[0] = sz;

  if (jit_fd != NULL) {
    size_t ret = fwrite((void*)thread->_jit_dump_buffer, (sz+2*sizeof(unsigned int)+sizeof(unsigned long)), 1, jit_fd);
    assert(ret == 1, "debug");
    fflush(jit_fd);
  }
}
