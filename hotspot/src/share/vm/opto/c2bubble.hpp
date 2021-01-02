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

#ifndef SHARE_VM_OPTO_C2BUBBLE_HPP
#define SHARE_VM_OPTO_C2BUBBLE_HPP

#undef min
#undef max

#include <map>
#include <string>
#include <unistd.h>
#include "runtime/jniHandles.hpp"

#define DEFAULT_CHUNK_SIZE      65536
#define PAD_BY_4B(sz)   ((((sz)+3)/4)*4)

class Method;
class relocInfo;
class nmethod;

typedef struct _OM {
  int _pc_offset;
  int _omv_count;
  int _omv_data_size;
  char* _omv_data;
  int heap_size;
} OM;

typedef struct _OopMS {
  int heap_size;
  int _om_count;
  int _om_size;
  OM* _om_data;
} OopMS;

typedef struct _GrowArray {
  bool is_unused;
  int array_len;
  size_t* array_ptr;
} GrowArray;

typedef struct _OopRec {
  bool is_unused;
  GrowArray oops;
  GrowArray metadata;
} OopRec;

typedef struct _CodeSec {
  size_t _start;
  size_t _end;
  size_t _limit;
  int _start_end_len;
  char* _start_end;
  int _locs_start_locs_end_len;
  char* _locs_start_locs_end;
  int locs_point_off;
  bool _frozen;
  int _index;
} CodeSec;

typedef struct _CodeBuf {
  int total_relocation_size;
  int total_offset_of_insts;
  int total_offset_of_consts;
  int total_offset_of_stubs;
  int total_content_size;
  CodeSec _consts;
  CodeSec _insts;
  CodeSec _stubs;
  OopRec OopRecorder;
  int total_oop_size;
  int total_metadata_size;
} CodeBuf;

typedef struct _Dep {
  size_t size_in_bytes;
  char* content_bytes;
} Dep;

typedef struct _ScopesPcs {
  int _pcs_offset;
  int _scope_decode_offset;
  int _obj_decode_offset;
  int _flags;
} ScopesPcs;

typedef struct _DebugInfoRec {
  char* scopes_data;
  int scopes_data_len;
  ScopesPcs* scopes_pcs;
  int scopes_pcs_cnt;
  int pcs_size;
  int data_size;
} DebugInfoRec;

typedef struct _ExpHandlerTable {
  int size_in_bytes;
  int len;
  char* data;
} ExpHandlerTable;

typedef struct _ImpHandlerTable {
  int size_in_bytes;
  int len;
  char* data;
  int _len;
} ImpHandlerTable;

typedef struct _BubbleOp {
  // Dynamic fields
  int bubble_total_cnt;
  int bubble_size_CodeEntryAlignment;
  std::map<int, int       >* insert_insts_len;
  std::map<int, void*     >* insert_insts;
  std::map<int, int       >* bubble_loc;
  std::map<int, int       >* flip_from;
  std::map<int, int       >* flip_to;
  std::map<int, int       >* branch_limit;
} BubbleOp;

#define MAX_TRACE_CNT		10240
typedef struct _TraceBranch {
  long thread_id;
  long trace_hash;
  long trace_idx;
  int trace[MAX_TRACE_CNT];
  int trace_stack[32768];
} TraceBranch;

#define MAX_SAMPLE_CNT		65536
typedef struct _TraceTick {
  long tick_begin;
  long tick_end;
  long tick_debug;
  long total_cnt;
  long entry_idx;
  long entry[MAX_SAMPLE_CNT];
} TraceTick;

typedef struct _JITTrace {
  TraceBranch* tb;
  TraceTick* tt;
  std::map<int, int  >* segment_report_map;
  std::map<long, int >* branch_population_map;
  std::map<long, int >* branch_steps_cnt_map;
  std::map<long, int*>* branch_steps_entry_map;
  std::map<int, int  >* branch_target_map;
  std::map<int, u8   >* branch_statistics;
  int max_branch_idx;
  float overhead_avg;
  float overhead_dev;
} JITTrace;

typedef struct _JITCode {
  Method* method;
  char method_name[1024];
  bool alive;
  bool compile_in_progress;
  bool profile_done;
  address live_insts_begin;
  int live_insts_size;
  int flip_tail_idx;

  /* Begin of nmethod */
  // Static fields
  int compile_id;
  int entry_bci;
  int CodeOffSets[8];
  int orig_pc_offset;
  DebugInfoRec DebugInformationRecorder;
  Dep Dependencies;
  CodeBuf CodeBuffer;
  int frame_size;
  OopMS OopMapSet;
  ExpHandlerTable ExceptionHandlerTable;
  ImpHandlerTable ImplicitExceptionTable;
  int comp_level;
  int nmethod_allocation_size;
  int bd_header;
  int bd_reloc;
  int bd_total_content;
  int bd_oop_metadata;
  bool has_unsafe_access;
  bool has_wide_vectors;
  std::map<jobject, jweak>* jobj_jweak_map;
  std::map<int, int      >* bubble_clearance;
  /* End of nmethod */

  // JIT Trace results
  JITTrace* jt;              // Persistent
  // Bubble operations
  BubbleOp* bub;             // Temporary, operations for one compilation
} JITCode;

typedef std::map<int, JITCode*> JITCodeMap;

typedef struct _ChunkBuffer {
  int capacity;
  char* hdr;
  int len;
  char* ptr;
} ChunkBuffer;

extern FILE *jit_fd;

#endif // SHARE_VM_OPTO_C2BUBBLE_HPP
