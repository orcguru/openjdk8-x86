#!/usr/bin/perl
use warnings;
use strict;

if ($#ARGV < 0) {
  print "Usage: ./JITBinDump.pl <jit_bin file> <txt decode file>\n";
  exit 1;
}
my $relocInfo_sz = 2;
my $lg_H = 6;
my $H = 1<<$lg_H;
my $BitsPerByte = 8;
my $L = (1<<$BitsPerByte)-$H;
my $MAX_i = 4;
my $type_mask_in_place = (1<<5)-1;
my $LOCATION_CODE = 0;
my $CONSTANT_INT_CODE = 1;
my $CONSTANT_OOP_CODE = 2;
my $CONSTANT_LONG_CODE = 3;
my $CONSTANT_DOUBLE_CODE = 4;
my $OBJECT_CODE = 5;
my $OBJECT_ID_CODE = 6;
my $input_fn = $ARGV[0];
my $output_fn = $input_fn.".txt";
if ($#ARGV > 0) {
  $output_fn = $ARGV[1];
}
my $in_fh;
my $out_fh;
open $in_fh, "< $input_fn" or die "Cannot open $input_fn for read!\n";
open $out_fh, "> $output_fn" or die "Cannot open $output_fn for write!\n";
my $bytes;
my $br = 0;
my $value_width = 2*8;
my $type_width = 4;
my $nontype_width = $value_width - $type_width;
my $datalen_width = $nontype_width-1;
my $datalen_tag = 1 << $datalen_width;
my $datalen_limit = 1 << $datalen_width;
my $datalen_mask = (1 << $datalen_width)-1;
my $format_width = 1;
my $offset_unit = 4;
my $offset_width = $nontype_width-$format_width;
my $offset_mask = (1<<$offset_width)-1;
my $format_mask = (1<<$format_width)-1;

# Methods
while (1) {
  my $cnt = 0;
  $br = read $in_fh, $bytes, 4;
  exit unless $br == 4;
  
  my $magic = unpack 'a4', $bytes;
  if ($magic eq "ERRO") {
    print $out_fh "\nERROR due to class byte code retransform/redefine\n";
    exit;
  }
  if ($magic eq "JITB") {
    my $hash_bin = read $in_fh, $bytes, 8;
    exit unless $hash_bin == 8;
    my $method_hash = unpack 'L', $bytes;
    $br = read $in_fh, $bytes, 4;
    exit unless $br == 4;
    my $method_sz = unpack 'I', $bytes;
    $br = read $in_fh, $bytes, $method_sz;
    exit unless $br == $method_sz;
    my ($space, $length) = unpack 'v v', $bytes;
    $cnt = 2+2;
    $length = $length-1;
    my $method_name = unpack "x$cnt a$length", $bytes;
    $cnt = $cnt+$space;
    print $out_fh "============================================\n";
    print $out_fh "method_name: $method_name\n";
    print $out_fh "hash: $method_hash\n";
    my $compile_id = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "compile_id: $compile_id\n";
    my $entry_bci = unpack "x$cnt i", $bytes;
    $cnt = $cnt+4;
    print $out_fh "entry_bci: $entry_bci\n";
    # CodeOffsets::max_Entries
    my $entries = unpack "x$cnt i", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  Entry: $entries\n";
    $entries = unpack "x$cnt i", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  Verified_Entry: $entries\n";
    $entries = unpack "x$cnt i", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  Frame_Complete: $entries\n";
    $entries = unpack "x$cnt i", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  OSR_Entry: $entries\n";
    $entries = unpack "x$cnt i", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  Exceptions: $entries\n";
    $entries = unpack "x$cnt i", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  Deopt: $entries\n";
    $entries = unpack "x$cnt i", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  DeoptMH: $entries\n";
    $entries = unpack "x$cnt i", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  UnwindHandler: $entries\n";
    # orig_pc_offset
    my $orig_pc_offset = unpack "x$cnt i", $bytes;
    $cnt = $cnt+4;
    print $out_fh "orig_pc_offset: $orig_pc_offset\n";
    # DebugInformationRecorder
    my $scopes_data_space = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    my $scopes_data_length = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    #print $out_fh "DebugInformationRecorder.scopes_data: ";
    my $idx = 0;
    my $cnt_tmp;
    my @scopes_data = ();
    while ($idx < $scopes_data_length) {
      $cnt_tmp = $cnt+$idx;
      my $c_value = unpack "x$cnt_tmp C", $bytes;
      push @scopes_data, $c_value;
      my $output = sprintf("%02X", $c_value);
      #print $out_fh "$output";
      $idx = $idx+1;
    }
    #print $out_fh "\n";
    $cnt = $cnt+$scopes_data_space;
    my $scopes_pcs_cnt = unpack "x$cnt v", $bytes;
    $cnt = $cnt+2;
    print $out_fh "DebugInformationRecorder.scopes_pcs\n  Count: $scopes_pcs_cnt\n";
    my $scope_idx = 0;
    while ($scope_idx < $scopes_pcs_cnt) {
      my $pcs_offset = unpack "x$cnt i", $bytes;
      $cnt = $cnt+4;
      print $out_fh "    _pcs_offset: $pcs_offset ";
      my $scope_decode_offset = unpack "x$cnt i", $bytes;
      $cnt = $cnt+4;
      #print $out_fh "_scope_decode_offset: $scope_decode_offset ";
      my $obj_decode_offset = unpack "x$cnt i", $bytes;
      $cnt = $cnt+4;
      #print $out_fh "_obj_decode_offset: $obj_decode_offset ";
      my $flags = unpack "x$cnt i", $bytes;
      $cnt = $cnt+4;
      print $out_fh "_flags: ";
      if ($flags != 0) {
        if ($flags & 1) {
          print $out_fh "should_reexec/";
        }
        if ($flags & 2) {
          print $out_fh "is_MH_invoke/";
        }
        if ($flags & 4) {
          print $out_fh "return_oop";
        }
      }
      #print $out_fh "\n";
      # Decode scopes data
      if ($scope_decode_offset != 0) {
        my $pos = $scope_decode_offset;
        my ($sender_stream_offset, $oop_rec_metadata_idx, $bci, $locals, $expressions, $monitors, $new_pos);
        ($sender_stream_offset, $new_pos) = read_int(\@scopes_data, $pos);
        $pos = $new_pos;
        ($oop_rec_metadata_idx, $new_pos) = read_int(\@scopes_data, $pos);
        $pos = $new_pos;
        ($bci, $new_pos) = read_bci(\@scopes_data, $pos);    
        $pos = $new_pos;
        ($locals, $new_pos) = read_int(\@scopes_data, $pos);
        $pos = $new_pos;
        ($expressions, $new_pos) = read_int(\@scopes_data, $pos);
        $pos = $new_pos;
        ($monitors, $new_pos) = read_int(\@scopes_data, $pos);
        $pos = $new_pos;
        print $out_fh " sender_stream_offset$sender_stream_offset/oop_rec_metadata_idx$oop_rec_metadata_idx/bci$bci ";
        if ($locals != 0) {
          print $out_fh "locals";
          my $val_len;
          ($val_len, $new_pos) = read_int(\@scopes_data, $locals);
          $pos = $new_pos;
          print $out_fh "($val_len) ";
          my $idx = 0;
          while ($idx < $val_len) {
            my @sv = parse_scope_value(\@scopes_data, $pos);
            $pos = $sv[@sv-1];
            my $idx2 = 0;
            while ($idx2 < @sv-2) {
              print $out_fh "$sv[$idx2]/";
              $idx2 = $idx2+1;
            }
            print $out_fh "$sv[$idx2];;";
            $idx = $idx+1;
          }
        }
        if ($expressions != 0) {
          print $out_fh " expressions";
          my $val_len;
          ($val_len, $new_pos) = read_int(\@scopes_data, $expressions);
          $pos = $new_pos;
          print $out_fh "($val_len) ";
          my $idx = 0;
          while ($idx < $val_len) {
            my @sv = parse_scope_value(\@scopes_data, $pos);
            $pos = $sv[@sv-1];
            my $idx2 = 0;
            while ($idx2 < @sv-2) {
              print $out_fh "$sv[$idx2]/";
              $idx2 = $idx2+1;
            }
            print $out_fh "$sv[$idx2];;";
            $idx = $idx+1;
          }
        }
        if ($monitors != 0) {
          print $out_fh " monitors";
          my $val_len;
          ($val_len, $new_pos) = read_int(\@scopes_data, $monitors);
          $pos = $new_pos;
          print $out_fh "($val_len) ";
          my $idx = 0;
          while ($idx < $val_len) {
            my @sv = parse_monitor_value(\@scopes_data, $pos);
            $pos = $sv[@sv-1];
            my $idx2 = 0;
            while ($idx2 < @sv-2) {
              print $out_fh "$sv[$idx2]/";
              $idx2 = $idx2+1;
            }
            print $out_fh "$sv[$idx2];;";
            $idx = $idx+1;
          }
        }
      }
      if ($obj_decode_offset != 0) {
        print $out_fh " obj";
        my ($val_len, $new_pos, $pos);
        ($val_len, $new_pos) = read_int(\@scopes_data, $obj_decode_offset);
        $pos = $new_pos;
        print $out_fh "($val_len) ";
        my $idx = 0;
        while ($idx < $val_len) {
          my @sv = parse_scope_value(\@scopes_data, $pos);
          $pos = $sv[@sv-1];
          my $idx2 = 0;
          while ($idx2 < @sv-2) {
            print $out_fh "$sv[$idx2]/";
            $idx2 = $idx2+1;
          }
          print $out_fh "$sv[$idx2];;";
          $idx = $idx+1;
        }
      }
      print $out_fh "\n";
      $scope_idx = $scope_idx+1;
    }
    # Dependencies
    my $size_in_bytes = unpack "x$cnt q", $bytes;
    $cnt = $cnt+8;
    #print $out_fh "Dependencies.size_in_bytes: $size_in_bytes\n";
    $space = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "Dependencies:\n";
    $idx = 0;
    my @dep = ();
    while ($idx < $size_in_bytes) {
      $cnt_tmp = $cnt+$idx;
      my $c_value = unpack "x$cnt_tmp C", $bytes;
      push @dep, $c_value;
      my $output = sprintf("%02X", $c_value);
      #print $out_fh "$output";
      $idx = $idx+1;
    }
    #print $out_fh "\n";
    $cnt = $cnt+$space;
  
    $idx = 0;
    my $dep_c = 0;
    while ($idx < @dep) {
      my ($val, $new_idx) = read_b(\@dep, $idx);
      $idx = $new_idx;
      if ($val == 0) {
        print $out_fh "  end_marker\n";
        last;
      } else {
        #print $out_fh "  read_b: $val ";
        my $ctxk_bit = ($val & (1<<4));
        my ($dep_type, $stride) = parse_dep_type($val - $ctxk_bit);
        print $out_fh "  $dep_type ";
        my $skipj = -1;
        if ($ctxk_bit != 0) {
          $skipj = 0;
        }
        my $i = 0;
        while ($i < $stride) {
          if ($i == $skipj) {
            print $out_fh "0 ";
          } else {
            my ($v, $new_idx) = read_int(\@dep, $idx);
            $idx = $new_idx;
            print $out_fh "$v ";
          }
          $i = $i + 1;
        }
        print $out_fh "\n";
      }
    }
  
    # CodeBuffer
    print $out_fh "CodeBuffer\n";
    my $total_relocation_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  total_relocation_size: $total_relocation_size\n";
    my $total_offset_of_insts = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  total_offset_of_insts: $total_offset_of_insts\n";
    my $total_offset_of_consts = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  total_offset_of_consts: $total_offset_of_consts\n";
    my $total_offset_of_stubs = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  total_offset_of_stubs: $total_offset_of_stubs\n";
    my $total_content_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "  total_content_size: $total_content_size\n";
    # CodeBuffer::consts
    $cnt = code_section($bytes, $cnt, "consts");
    # CodeBuffer::insts
    $cnt = code_section($bytes, $cnt, "insts");
    # CodeBuffer::stubs
    $cnt = code_section($bytes, $cnt, "stubs");
    # OopRecorder
    my $oop_rec_is_unused = unpack "x$cnt C", $bytes;
    $cnt = $cnt+1;
    print $out_fh "OopRecorder.is_unused: $oop_rec_is_unused\n";
    my $oops_is_unused = unpack "x$cnt C", $bytes;
    $cnt = $cnt+1;
    print $out_fh "  oops.is_unused: $oops_is_unused\n";
    my $count = 0;
    if ($oops_is_unused == 0) {
      $count = unpack "x$cnt v", $bytes;
      $cnt = $cnt+2;
      print $out_fh "  oops.handles_count: $count\n";
      $idx = 0;
      while ($idx < $count) {
        my $oops_handle = unpack "x$cnt Q", $bytes;
        $cnt = $cnt+8;
        print $out_fh "    $oops_handle\n";
        $idx = $idx+1;
      }
    }
    my $metadata_is_unused = unpack "x$cnt C", $bytes;
    $cnt = $cnt+1;
    print $out_fh "  metadata.is_unused: $metadata_is_unused\n";
    if ($metadata_is_unused == 0) {
      $count = unpack "x$cnt v", $bytes;
      $cnt = $cnt+2;
      print $out_fh "  metadata.handles_count: $count\n";
      $idx = 0;
      while ($idx < $count) {
        my $metadata_handle = unpack "x$cnt Q", $bytes;
        $cnt = $cnt+8;
        print $out_fh "    $metadata_handle\n";
        $idx = $idx+1;
      }
    }
    # framesize
    my $frame_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "frame_size: $frame_size\n";
    my $oop_map_set_exists = unpack "x$cnt C", $bytes;
    $cnt = $cnt+1;
    if ($oop_map_set_exists != 0) {
      # heap_size/_om_count/_om_size
      my $heap_size = unpack "x$cnt I", $bytes;
      $cnt = $cnt+4;
      print $out_fh "OopMapSet\n  heap_size: $heap_size\n";
      my $om_count = unpack "x$cnt I", $bytes;
      $cnt = $cnt+4;
      print $out_fh "  om_count: $om_count\n";
      my $om_size = unpack "x$cnt I", $bytes;
      $cnt = $cnt+4;
      print $out_fh "  om_size: $om_size\n";
      $count = 0;
      while ($count < $om_count) {
        my $pc_offset = unpack "x$cnt i", $bytes;
        $cnt = $cnt+4;
        print $out_fh "    pc_offset: $pc_offset ";
  
        my $omv_count = unpack "x$cnt i", $bytes;
        $cnt = $cnt+4;
        print $out_fh "omv_count: $omv_count ";
  
        my $omv_data_size = unpack "x$cnt i", $bytes;
        $cnt = $cnt+4;
        print $out_fh "omv_data_size: $omv_data_size ";
  
        my $omv_data_space = unpack "x$cnt I", $bytes;
        $cnt = $cnt+4;
        my $omv_data_length = unpack "x$cnt I", $bytes;
        $cnt = $cnt+4;
        $idx = 0;
        print $out_fh "omv_data: ";
        my @omv_data = ();
        while ($idx < $omv_data_length) {
          $cnt_tmp = $cnt+$idx;
          my $c_value = unpack "x$cnt_tmp C", $bytes;
          push @omv_data, $c_value;
          my $output = sprintf("%02X", $c_value);
          #print $out_fh "$output";
          $idx = $idx+1;
        }
        #print $out_fh " ";
        $cnt = $cnt+$omv_data_space;
  
        # Parse the omv_data
        my $pos = 0;
        my $omv_c = 0;
        while ($pos < @omv_data and $omv_c < $omv_count) {
          my ($val, $new_pos) = read_int(\@omv_data, $pos);
          $pos = $new_pos;
          my $need_read_int = 0;
          my $show_val = $val>>5;
          print $out_fh "/$show_val ";
          if (($val & $type_mask_in_place) == 1) {
            print $out_fh "is_oop ";
          }
          if (($val & $type_mask_in_place) == 2) {
            print $out_fh "is_value ";
          }
          if (($val & $type_mask_in_place) == 4) {
            print $out_fh "is_narrowoop ";
          }
          if (($val & $type_mask_in_place) == 8) {
            $need_read_int = 1;
            print $out_fh "is_callee_saved ";
          } 
          if (($val & $type_mask_in_place) == 16) {
            $need_read_int = 1;
            print $out_fh "is_derived_oop ";
          }
          if ($need_read_int == 1) {
            ($val, $new_pos) = read_int(\@omv_data, $pos);
            $show_val = $val>>5;
            print $out_fh "reg$show_val";
          }
          $omv_c = $omv_c+1;
        }
  
        $heap_size = unpack "x$cnt i", $bytes;
        $cnt = $cnt+4;
        print $out_fh " heap_size: $heap_size\n";
  
        $count = $count+1;
      }
    }
    # ExceptionHandlerTable
    my $exp_size_in_bytes = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "ExceptionHandlerTable.size_in_bytes: $exp_size_in_bytes\n";
    my $exp_table_space = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    my $exp_table_length = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    $idx = 0;
    $cnt_tmp = $cnt+$idx;
    print $out_fh "ExceptionHandlerTable.table:\n";
    while ($idx < $exp_table_length) {
      my $c_value = unpack "x$cnt_tmp I", $bytes;
      if ($c_value == 4294967295) {
        print $out_fh "  bci:-1 ";
      } else {
        print $out_fh "  bci:$c_value ";
      }
      $idx = $idx+4;
      $cnt_tmp = $cnt+$idx;
      $c_value = unpack "x$cnt_tmp I", $bytes;
      print $out_fh "pco:$c_value ";
      $idx = $idx+4;
      $cnt_tmp = $cnt+$idx;
      $c_value = unpack "x$cnt_tmp I", $bytes;
      print $out_fh "scope_depth:$c_value\n";
      $idx = $idx+4;
      $cnt_tmp = $cnt+$idx;
    }
    $cnt = $cnt+$exp_table_space;
    # ImplicitExceptionTable
    my $imp_size_in_bytes = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "ImplicitExceptionTable.size_in_bytes: $imp_size_in_bytes\n";
    my $imp_data_space = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    my $imp_data_length = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    $idx = 0;
    print $out_fh "ImplicitExceptionTable.data:\n";
    if ($imp_size_in_bytes > 0) {
      my $imp_cnt = ($imp_size_in_bytes-4)/8;
      while ($idx < $imp_cnt) {
        $cnt_tmp = $cnt+$idx*8;
        my $c_value = unpack "x$cnt_tmp I", $bytes;
        print $out_fh "  exception-offset $c_value ";
        $cnt_tmp = $cnt+$idx*8+4;
        $c_value = unpack "x$cnt_tmp I", $bytes;
        print $out_fh "continue-offset $c_value\n";
        $idx = $idx+1;
      }
    }
    $cnt = $cnt+$imp_data_space;
    my $imp_len = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "ImplicitExceptionTable.len: $imp_len\n";
    my $comp_level = unpack "x$cnt v", $bytes;
    $cnt = $cnt+2;
    print $out_fh "comp_level: $comp_level\n";
    my $nmethod_alloc_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "nmethod.allocation_size: $nmethod_alloc_size\n";
    # DebugInformationRecorder
    my $pcs_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "DebugInformationRecorder.pcs_size: $pcs_size\n";
    my $data_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "DebugInformationRecorder.data_size: $data_size\n";
    # CodeBuffer
    my $total_oop_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "CodeBuffer.total_oop_size: $total_oop_size\n";
    my $total_metadata_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "CodeBuffer.total_metadata_size: $total_metadata_size  \n";
  
    # misc
    my $has_unsafe_access = unpack "x$cnt C", $bytes;
    $cnt = $cnt+1;
    print $out_fh "has_unsafe_access: $has_unsafe_access\n";
    my $has_wide_vectors = unpack "x$cnt C", $bytes;
    $cnt = $cnt+1;
    print $out_fh "has_wide_vectors: $has_wide_vectors\n\n";
  
    if ($cnt != $method_sz) {
      die "Method data format error!\n";
    }
  } elsif ($magic eq "JITN") {
    my $idx = 0;
    my $hash_bin = read $in_fh, $bytes, 8;
    exit unless $hash_bin == 8;
    my $method_hash = unpack 'L', $bytes;
    $br = read $in_fh, $bytes, 4;
    exit unless $br == 4;
    my $method_sz = unpack 'I', $bytes;
    $br = read $in_fh, $bytes, $method_sz;
    exit unless $br == $method_sz;
    my ($space, $length) = unpack 'v v', $bytes;
    $cnt = 2+2;
    $length = $length-1;
    my $method_name = unpack "x$cnt a$length", $bytes;
    $cnt = $cnt+$space;
    print $out_fh "++++++++++++++++++++++++++++++++++++++++++++\n";
    print $out_fh "method_name: $method_name\n";
    print $out_fh "hash: $method_hash\n";
    my $entry_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "entry_point_offset: $entry_offset\n";
    my $verified_entry_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "verified_entry_point_offset: $verified_entry_offset\n";
    my $exception_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "exception_offset: $exception_offset\n";
    my $deoptimize_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "deoptimize_offset: $deoptimize_offset\n";
    my $deopt_mh_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "deopt_mh_offset: $deopt_mh_offset\n";
    my $unwind_handler_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "unwind_handler_offset: $unwind_handler_offset\n";
    my $consts_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "consts_offset: $consts_offset\n";
    my $stub_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "stub_offset: $stub_offset\n";
    my $oops_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "oops_offset: $oops_offset\n";
    my $metadata_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "metadata_offset: $metadata_offset\n";
    my $scopes_data_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "scopes_data_offset: $scopes_data_offset\n";
    my $scopes_pcs_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "scopes_pcs_offset: $scopes_pcs_offset\n";
    my $dependencies_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "dependencies_offset: $dependencies_offset\n";
    my $handler_table_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "handler_table_offset: $handler_table_offset\n";
    my $nul_chk_table_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "nul_chk_table_offset: $nul_chk_table_offset\n";
    my $nmethod_end_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "nmethod_end_offset: $nmethod_end_offset\n";
    my $orig_oc_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "orig_oc_offset: $orig_oc_offset\n";
    my $compile_id = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "compile_id: $compile_id\n";
    my $comp_level = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "comp_level: $comp_level\n";
    my $size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "size: $size\n";
    my $header_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "header_size: $header_size\n";
    my $relocation_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "relocation_size: $relocation_size\n";
    my $content_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "content_offset: $content_offset\n";
    my $code_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "code_offset: $code_offset\n";
    my $frame_complete_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    if ($frame_complete_offset == 4294967295) {
      $frame_complete_offset = -1;
    }
    print $out_fh "frame_complete_offset: $frame_complete_offset\n";
    my $data_offset = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "data_offset: $data_offset\n";
    my $frame_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "frame_size: $frame_size\n";
    my $oop_map_set_exists = unpack "x$cnt C", $bytes;
    $cnt = $cnt+1;
    if ($oop_map_set_exists != 0) {
      # heap_size/_om_count/_om_size
      my $om_count = unpack "x$cnt I", $bytes;
      $cnt = $cnt+4;
      print $out_fh "OopMapSet\n  om_count: $om_count\n";
      my $om_size = unpack "x$cnt I", $bytes;
      if ($om_size == 4294967295) {
        $om_size = -1;
      }
      $cnt = $cnt+4;
      print $out_fh "  om_size: $om_size\n";
      my $count = 0;
      while ($count < $om_count) {
        my $pc_offset = unpack "x$cnt i", $bytes;
        $cnt = $cnt+4;
        print $out_fh "    pc_offset: $pc_offset ";
  
        my $omv_count = unpack "x$cnt i", $bytes;
        $cnt = $cnt+4;
        print $out_fh "omv_count: $omv_count ";
  
        my $omv_data_size = unpack "x$cnt i", $bytes;
        $cnt = $cnt+4;
        print $out_fh "omv_data_size: $omv_data_size ";
  
        my $omv_data_space = unpack "x$cnt I", $bytes;
        $cnt = $cnt+4;
        my $omv_data_length = unpack "x$cnt I", $bytes;
        $cnt = $cnt+4;
        $idx = 0;
        print $out_fh "omv_data: ";
        my @omv_data = ();
        my $cnt_tmp = 0;
        while ($idx < $omv_data_length) {
          $cnt_tmp = $cnt+$idx;
          my $c_value = unpack "x$cnt_tmp C", $bytes;
          push @omv_data, $c_value;
          my $output = sprintf("%02X", $c_value);
          #print $out_fh "$output";
          $idx = $idx+1;
        }
        #print $out_fh " ";
        $cnt = $cnt+$omv_data_space;
  
        # Parse the omv_data
        my $pos = 0;
        my $omv_c = 0;
        while ($pos < @omv_data and $omv_c < $omv_count) {
          my ($val, $new_pos) = read_int(\@omv_data, $pos);
          $pos = $new_pos;
          my $need_read_int = 0;
          my $show_val = $val>>5;
          print $out_fh "/$show_val ";
          if (($val & $type_mask_in_place) == 1) {
            print $out_fh "is_oop ";
          }
          if (($val & $type_mask_in_place) == 2) {
            print $out_fh "is_value ";
          }
          if (($val & $type_mask_in_place) == 4) {
            print $out_fh "is_narrowoop ";
          }
          if (($val & $type_mask_in_place) == 8) {
            $need_read_int = 1;
            print $out_fh "is_callee_saved ";
          } 
          if (($val & $type_mask_in_place) == 16) {
            $need_read_int = 1;
            print $out_fh "is_derived_oop ";
          }
          if ($need_read_int == 1) {
            ($val, $new_pos) = read_int(\@omv_data, $pos);
            $show_val = $val>>5;
            print $out_fh "reg$show_val";
          }
          $omv_c = $omv_c+1;
        }
        $count = $count+1;
        print $out_fh "\n";
      }
    } else {
      print $out_fh "OopMapSet NULL\n";
    }
    my $insts_addr = unpack "x$cnt Q", $bytes;
    $cnt = $cnt+8;
    my $insts_addr_hex = sprintf "%x", $insts_addr;
    print $out_fh "Insts address: $insts_addr_hex\n";
    my $code_size = unpack "x$cnt I", $bytes;
    $cnt = $cnt+4;
    print $out_fh "CodeSize: $code_size\n";

    my $cnt_tmp;
    my @code_data = ();
    $idx = 0;
    while ($idx < $code_size) {
      $cnt_tmp = $cnt+$idx;
      my $c_value = unpack "x$cnt_tmp C", $bytes;
      push @code_data, $c_value;
      my $output = sprintf("%02X", $c_value);
      print $out_fh "$output";
      $idx = $idx+1;
    }
    print $out_fh "\n";
    #$cnt = $cnt+$code_size;

    # Parse CodeData
    # relocInfo
    my $reloc_ptr = 0;
    my $total_offset = 0;
    print $out_fh "RelocInfo\n";
    my $reloc_address = $insts_addr - $code_offset + $header_size;
    while ($reloc_ptr < $relocation_size) {
      my $cnt_tmp = $cnt+$reloc_ptr;
      my $value = unpack "x$cnt_tmp S", $bytes;
      my $type = $value >> $nontype_width;
      my $format = $format_mask & ($value>>$offset_width);
      if ($type <= 14) {
        my $type_str = sprintf "%-24s", int2reloc_type($type);
        my $offset = ($value & $offset_mask)*$offset_unit;
        $total_offset = $total_offset+$offset;
        my $t_offset_str = sprintf "%x", $total_offset;
        my $reloc_addr_hex = sprintf "%x", ($reloc_address + $reloc_ptr);
        print $out_fh "    $type_str, format/$format, t_offset $t_offset_str relocInfo:$reloc_addr_hex\n";
      } elsif ($type == 15) {
        my $is_immediate_flag = $value & $datalen_tag;
        my $type_str = sprintf "%-24s", "data_prefix_tag";
        print $out_fh "    $type_str, format/$format, ";
        if ($is_immediate_flag == 0) {
          my $immediate = $value & $datalen_mask;
          print $out_fh "immediate:$immediate ";
        } else {
          my $datalen = $value & $datalen_mask;
          print $out_fh "datalen:$datalen ";
          my $datalen_cnt = $cnt+$reloc_ptr+$relocInfo_sz;
          $datalen = $datalen*2;
          $idx = 0;
          while ($idx < $datalen) {
            my $c_value = unpack "x$datalen_cnt C", $bytes;
            my $output = sprintf("%02x", $c_value);
            print $out_fh "$output";
            $idx = $idx+1;
            $datalen_cnt = $datalen_cnt+1;
          }
          $reloc_ptr = $reloc_ptr+$datalen;
        }
        print $out_fh "\n";
      } else {
        die "BUG";
      }
      $reloc_ptr = $reloc_ptr+$relocInfo_sz;
    }
    print $out_fh "RelocInfo binary:\n";
    $idx = 0;
    while ($idx < $relocation_size) {
      $cnt_tmp = $cnt+$idx;
      my $c_value = unpack "x$cnt_tmp C", $bytes;
      my $output = sprintf("%02x", $c_value);
      print $out_fh "$output";
      $idx = $idx+1;
    }
    print $out_fh "\n";
    $cnt = $cnt+$relocation_size;
    if ($content_offset < ($header_size + $relocation_size)) {
      die "JITN method:$method_name error: content_offset($content_offset) < (header_size($header_size)+relocation_size($relocation_size))!\n";
    }
    if ($content_offset > ($header_size + $relocation_size)) {
      print $out_fh "Gap between relocInfo and content:\n";
      $idx = 0;
      while ($idx < ($content_offset - ($header_size + $relocation_size))) {
        $cnt_tmp = $cnt+$idx;
        my $c_value = unpack "x$cnt_tmp C", $bytes;
        my $output = sprintf("%02X", $c_value);
        print $out_fh "$output";
        $idx = $idx+1;
      }
      print $out_fh "\n";
      $cnt = $cnt + ($content_offset - ($header_size + $relocation_size));
    }
    
    # Constant section with padding
    print $out_fh "Consts with padding:\n";
    $idx = 0;
    while ($idx < ($code_offset - $content_offset)) {
      $cnt_tmp = $cnt+$idx;
      my $l_value = unpack "x$cnt_tmp Q", $bytes;
      my $l_idx = sprintf "%03x", $idx;
      my $l_str = sprintf "%x", $l_value;
      print $out_fh "  $l_idx: $l_str\n";
      $idx = $idx+8;
    }
    $cnt = $cnt + ($code_offset - $content_offset);

    # Code section (insts)
    print $out_fh "Insts + Stubs:\n";
    my $bin_data = substr $bytes, $cnt, ($data_offset - $code_offset);
    open(my $out, '>:raw', 'sample.bin') or die "Unable to open: $!";
    print $out $bin_data;
    close($out);
    my @disassemble = split /\n/, `objdump -m i386:x86-64 -D -b binary sample.bin`;
    $idx = 6;
    while ($idx <= $#disassemble) {
      print $out_fh "$disassemble[$idx]\n";
      $idx = $idx+1;
    }
    print $out_fh "\n";
    `rm -f sample.bin`;
    $cnt = $cnt + ($data_offset - $code_offset);

    # Oops
    print $out_fh "Oops:\n";
    $idx = 0;
    while ($idx < ($metadata_offset - $oops_offset)) {
      $cnt_tmp = $cnt+$idx;
      my $l_value = unpack "x$cnt_tmp Q", $bytes;
      my $l_str = sprintf "%x", $l_value;
      print $out_fh "  $l_str\n";
      $idx = $idx+8;
    }
    $cnt = $cnt + ($metadata_offset - $oops_offset);

    # Metadata
    print $out_fh "Metadata:\n";
    $idx = 0;
    while ($idx < ($scopes_data_offset - $metadata_offset)) {
      $cnt_tmp = $cnt+$idx;
      my $l_value = unpack "x$cnt_tmp Q", $bytes;
      my $l_str = sprintf "%x", $l_value;
      print $out_fh "  $l_str\n";
      $idx = $idx+8;
    }
    $cnt = $cnt + ($scopes_data_offset - $metadata_offset);

    # Scopes_data
    my @scopes_data = ();
    $idx = 0;
    while ($idx < ($scopes_pcs_offset - $scopes_data_offset)) {
      $cnt_tmp = $cnt+$idx;
      my $c_value = unpack "x$cnt_tmp C", $bytes;
      push @scopes_data, $c_value;
      my $output = sprintf("%02X", $c_value);
      $idx = $idx+1;
    }
    $cnt = $cnt + ($scopes_pcs_offset - $scopes_data_offset);

    # Scopes_pcs
    print $out_fh "Scope PCS:\n";
    $idx = 0;
    while ($idx < ($dependencies_offset - $scopes_pcs_offset)) {
      $cnt_tmp = $cnt+$idx;
      my $pcs_offset = unpack "x$cnt_tmp i", $bytes;
      $idx = $idx+4;
      print $out_fh "    _pcs_offset: $pcs_offset ";
      $cnt_tmp = $cnt+$idx;
      my $scope_decode_offset = unpack "x$cnt_tmp i", $bytes;
      $idx = $idx+4;
      #print $out_fh "_scope_decode_offset: $scope_decode_offset ";
      $cnt_tmp = $cnt+$idx;
      my $obj_decode_offset = unpack "x$cnt_tmp i", $bytes;
      $idx = $idx+4;
      #print $out_fh "_obj_decode_offset: $obj_decode_offset ";
      $cnt_tmp = $cnt+$idx;
      my $flags = unpack "x$cnt_tmp i", $bytes;
      $idx = $idx+4;
      print $out_fh "_flags: ";
      if ($flags != 0) {
        if ($flags & 1) {
          print $out_fh "should_reexec/";
        }
        if ($flags & 2) {
          print $out_fh "is_MH_invoke/";
        }
        if ($flags & 4) {
          print $out_fh "return_oop";
        }
      }
      #print $out_fh "\n";
      # Decode scopes data
      if ($scope_decode_offset != 0) {
        my $pos = $scope_decode_offset;
        my ($sender_stream_offset, $oop_rec_metadata_idx, $bci, $locals, $expressions, $monitors, $new_pos);
        ($sender_stream_offset, $new_pos) = read_int(\@scopes_data, $pos);
        $pos = $new_pos;
        ($oop_rec_metadata_idx, $new_pos) = read_int(\@scopes_data, $pos);
        $pos = $new_pos;
        ($bci, $new_pos) = read_bci(\@scopes_data, $pos);    
        $pos = $new_pos;
        ($locals, $new_pos) = read_int(\@scopes_data, $pos);
        $pos = $new_pos;
        ($expressions, $new_pos) = read_int(\@scopes_data, $pos);
        $pos = $new_pos;
        ($monitors, $new_pos) = read_int(\@scopes_data, $pos);
        $pos = $new_pos;
        print $out_fh " sender_stream_offset$sender_stream_offset/oop_rec_metadata_idx$oop_rec_metadata_idx/bci$bci ";
        if ($locals != 0) {
          print $out_fh "locals";
          my $val_len;
          ($val_len, $new_pos) = read_int(\@scopes_data, $locals);
          $pos = $new_pos;
          print $out_fh "($val_len) ";
          my $idx = 0;
          while ($idx < $val_len) {
            my @sv = parse_scope_value(\@scopes_data, $pos);
            $pos = $sv[@sv-1];
            my $idx2 = 0;
            while ($idx2 < @sv-2) {
              print $out_fh "$sv[$idx2]/";
              $idx2 = $idx2+1;
            }
            print $out_fh "$sv[$idx2];;";
            $idx = $idx+1;
          }
        }
        if ($expressions != 0) {
          print $out_fh " expressions";
          my $val_len;
          ($val_len, $new_pos) = read_int(\@scopes_data, $expressions);
          $pos = $new_pos;
          print $out_fh "($val_len) ";
          my $idx = 0;
          while ($idx < $val_len) {
            my @sv = parse_scope_value(\@scopes_data, $pos);
            $pos = $sv[@sv-1];
            my $idx2 = 0;
            while ($idx2 < @sv-2) {
              print $out_fh "$sv[$idx2]/";
              $idx2 = $idx2+1;
            }
            print $out_fh "$sv[$idx2];;";
            $idx = $idx+1;
          }
        }
        if ($monitors != 0) {
          print $out_fh " monitors";
          my $val_len;
          ($val_len, $new_pos) = read_int(\@scopes_data, $monitors);
          $pos = $new_pos;
          print $out_fh "($val_len) ";
          my $idx = 0;
          while ($idx < $val_len) {
            my @sv = parse_monitor_value(\@scopes_data, $pos);
            $pos = $sv[@sv-1];
            my $idx2 = 0;
            while ($idx2 < @sv-2) {
              print $out_fh "$sv[$idx2]/";
              $idx2 = $idx2+1;
            }
            print $out_fh "$sv[$idx2];;";
            $idx = $idx+1;
          }
        }
      }
      if ($obj_decode_offset != 0) {
        print $out_fh " obj";
        my ($val_len, $new_pos, $pos);
        ($val_len, $new_pos) = read_int(\@scopes_data, $obj_decode_offset);
        $pos = $new_pos;
        print $out_fh "($val_len) ";
        my $idx = 0;
        while ($idx < $val_len) {
          my @sv = parse_scope_value(\@scopes_data, $pos);
          $pos = $sv[@sv-1];
          my $idx2 = 0;
          while ($idx2 < @sv-2) {
            print $out_fh "$sv[$idx2]/";
            $idx2 = $idx2+1;
          }
          print $out_fh "$sv[$idx2];;";
          $idx = $idx+1;
        }
      }
      print $out_fh "\n";
    }
    $cnt = $cnt + ($dependencies_offset - $scopes_pcs_offset);

    # Dependencies
    print $out_fh "Dependencies:\n";
    $idx = 0;
    my @dep = ();
    while ($idx < ($handler_table_offset - $dependencies_offset)) {
      $cnt_tmp = $cnt+$idx;
      my $c_value = unpack "x$cnt_tmp C", $bytes;
      push @dep, $c_value;
      my $output = sprintf("%02X", $c_value);
      $idx = $idx+1;
    }
    $cnt = $cnt + ($handler_table_offset - $dependencies_offset);
    $idx = 0;
    my $dep_c = 0;
    while ($idx < @dep) {
      my ($val, $new_idx) = read_b(\@dep, $idx);
      $idx = $new_idx;
      if ($val == 0) {
        print $out_fh "  end_marker\n";
        last;
      } else {
        #print $out_fh "  read_b: $val ";
        my $ctxk_bit = ($val & (1<<4));
        my ($dep_type, $stride) = parse_dep_type($val - $ctxk_bit);
        print $out_fh "  $dep_type ";
        my $skipj = -1;
        if ($ctxk_bit != 0) {
          $skipj = 0;
        }
        my $i = 0;
        while ($i < $stride) {
          if ($i == $skipj) {
            print $out_fh "0 ";
          } else {
            my ($v, $new_idx) = read_int(\@dep, $idx);
            $idx = $new_idx;
            print $out_fh "$v ";
          }
          $i = $i + 1;
        }
        print $out_fh "\n";
      }
    }

    # ExceptionHandlerTable
    $idx = 0;
    $cnt_tmp = $cnt+$idx;
    print $out_fh "ExceptionHandlerTable:\n";
    while ($idx < ($nul_chk_table_offset - $handler_table_offset)) {
      my $c_value = unpack "x$cnt_tmp I", $bytes;
      if ($c_value == 4294967295) {
        print $out_fh "  bci:-1 ";
      } else {
        print $out_fh "  bci:$c_value ";
      }
      $idx = $idx+4;
      $cnt_tmp = $cnt+$idx;
      $c_value = unpack "x$cnt_tmp I", $bytes;
      print $out_fh "pco:$c_value ";
      $idx = $idx+4;
      $cnt_tmp = $cnt+$idx;
      $c_value = unpack "x$cnt_tmp I", $bytes;
      print $out_fh "scope_depth:$c_value\n";
      $idx = $idx+4;
      $cnt_tmp = $cnt+$idx;
    }
    $cnt = $cnt + ($nul_chk_table_offset - $handler_table_offset);

    # ImplicitExceptionTable
    $idx = 0;
    print $out_fh "ImplicitExceptionTable:\n";
    if (($nmethod_end_offset - $nul_chk_table_offset) > 0) {
      my $imp_cnt = unpack "x$cnt I", $bytes;
      print $out_fh "  count:$imp_cnt\n";
      while ($idx < $imp_cnt) {
        $cnt_tmp = $cnt+4+$idx*8;
        my $c_value = unpack "x$cnt_tmp I", $bytes;
        print $out_fh "  exception-offset $c_value ";
        $cnt_tmp = $cnt+4+$idx*8+4;
        $c_value = unpack "x$cnt_tmp I", $bytes;
        print $out_fh "continue-offset $c_value\n";
        $idx = $idx+1;
      }
    }
    $cnt = $cnt + ($nmethod_end_offset - $nul_chk_table_offset);

    if ($cnt != $method_sz) {
      die "Method data format error!\n";
    }
  } else {
    die "Unexpected magic header:$magic\n";
  }
}

sub code_section
{
  my ($bytes, $cnt, $st) = @_;
  my $start = unpack "x$cnt Q", $bytes;
  $cnt = $cnt+8;
  print $out_fh "  $st._start: $start\n";
  my $end = unpack "x$cnt Q", $bytes;
  $cnt = $cnt+8;
  print $out_fh "  $st._end: $end\n";
  my $limit = unpack "x$cnt Q", $bytes;
  $cnt = $cnt+8;
  print $out_fh "  $st._limit: $limit\n";
  my $start_end_space = unpack "x$cnt I", $bytes;
  $cnt = $cnt+4;
  my $start_end_length = unpack "x$cnt I", $bytes;
  $cnt = $cnt+4;
  my $idx = 0;
  my $cnt_tmp;
  print $out_fh "  $st.start_end:\n";
  my $bin_data = substr $bytes, $cnt, $start_end_length;
  open(my $out, '>:raw', 'sample.bin') or die "Unable to open: $!";
  print $out $bin_data;
  close($out);
  my @disassemble = split /\n/, `objdump -m i386:x86-64 -D -b binary sample.bin`;
  $idx = 6;
  while ($idx <= $#disassemble) {
    print $out_fh "$disassemble[$idx]\n";
    $idx = $idx+1;
  }
  print $out_fh "\n";
  `rm -f sample.bin`;
  $cnt = $cnt+$start_end_space;
  my $locs_start_locs_end_space = unpack "x$cnt I", $bytes;
  $cnt = $cnt+4;
  my $locs_start_locs_end_length = unpack "x$cnt I", $bytes;
  $cnt = $cnt+4;
  $idx = 0;
  print $out_fh "  $st.locs_start_locs_end:\n";
  my $reloc_ptr = 0;
  my $total_offset = 0;
  while ($reloc_ptr < $locs_start_locs_end_length) {
    my $cnt_tmp = $cnt+$reloc_ptr;
    my $value = unpack "x$cnt_tmp S", $bytes;
    my $type = $value >> $nontype_width;
    my $format = $format_mask & ($value>>$offset_width);
    if ($type <= 14) {
      my $type_str = sprintf "%-24s", int2reloc_type($type);
      my $offset = ($value & $offset_mask)*$offset_unit;
      $total_offset = $total_offset+$offset;
      my $t_offset_str = sprintf "%x", $total_offset;
      print $out_fh "    $type_str, format/$format, t_offset $t_offset_str\n";
    } elsif ($type == 15) {
      my $is_immediate_flag = $value & $datalen_tag;
      my $type_str = sprintf "%-24s", "data_prefix_tag";
      print $out_fh "    $type_str, format/$format, ";
      if ($is_immediate_flag == 0) {
        my $immediate = $value & $datalen_mask;
        print $out_fh "immediate:$immediate ";
      } else {
        my $datalen = $value & $datalen_mask;
        print $out_fh "datalen:$datalen ";
        my $datalen_cnt = $cnt+$reloc_ptr+$relocInfo_sz;
        $datalen = $datalen*2;
        $idx = 0;
        while ($idx < $datalen) {
          my $c_value = unpack "x$datalen_cnt C", $bytes;
          my $output = sprintf("%02x", $c_value);
          print $out_fh "$output";
          $idx = $idx+1;
          $datalen_cnt = $datalen_cnt+1;
        }
        $reloc_ptr = $reloc_ptr+$datalen;
      }
      print $out_fh "\n";
    } else {
      die "BUG";
    }
    $reloc_ptr = $reloc_ptr+$relocInfo_sz;
  }
  $cnt = $cnt+$locs_start_locs_end_space;
  my $locs_point_off = unpack "x$cnt i", $bytes;
  $cnt = $cnt+4;
  print $out_fh "  $st.locs_point_off: $locs_point_off\n";
  my $frozen = unpack "x$cnt C", $bytes;
  $cnt = $cnt+1;
  print $out_fh "  $st.frozen: $frozen\n";
  my $index = unpack "x$cnt C", $bytes;
  $cnt = $cnt+1;
  print $out_fh "  $st.index: $index\n\n";
  return $cnt;
}

sub int2reloc_type
{
  my ($id) = @_;
  
  if ($id == 0) {
    return "none";
  } elsif ($id == 1) {
    return "oop_type";
  } elsif ($id == 2) {
    return "virtual_call_type";
  } elsif ($id == 3) {
    return "opt_virtual_call_type";
  } elsif ($id == 4) {
    return "static_call_type";
  } elsif ($id == 5) {
    return "static_stub_type";
  } elsif ($id == 6) {
    return "runtime_call_type";
  } elsif ($id == 7) {
    return "external_word_type";
  } elsif ($id == 8) {
    return "internal_word_type";
  } elsif ($id == 9) {
    return "section_word_type";
  } elsif ($id == 10) {
    return "poll_type";
  } elsif ($id == 11) {
    return "poll_return_type";
  } elsif ($id == 12) {
    return "metadata_type";
  } elsif ($id == 13) {
    return "trampoline_stub_type";
  } elsif ($id == 14) {
    return "yet_unused_type_1";
  } elsif ($id == 15) {
    return "data_prefix_tag";
  } else {
    return "BUG";
  }
}

sub read_b
{
  my ($buffer, $position) = @_;
  return (@{$buffer}[$position], ($position+1));
}

sub read_int
{
  my ($buffer, $position) = @_;
  my ($b0, $new_position) = read_b($buffer, $position);
  if ($b0 < $L) {
    return ($b0, $new_position);
  } else {
    return read_int_mb($buffer, $new_position, $b0);
  }
}

sub read_int_mb
{
  my ($buffer, $position, $b0) = @_;
  my $sum = $b0;
  my $lg_H_i = $lg_H;
  my $i = 0;
  my $pos = $position-1;
  while (1) {
    $i = $i+1;
    my $b_i = @{$buffer}[$pos+$i];
    $sum = $sum + ($b_i << $lg_H_i);
    if (($b_i < $L) or ($i == $MAX_i)) {
      return ($sum, ($pos+$i+1));
    }
    $lg_H_i = $lg_H_i + $lg_H;
  }
}

sub read_bci
{
  my ($buffer, $position) = @_;
  my ($ret, $new_pos) = read_int($buffer, $position);
  $ret = $ret-1;
  return ($ret, $new_pos);
}

sub read_long
{
  my ($buffer, $position) = @_;
  my ($low, $high, $new_pos);
  ($low, $new_pos) = read_int($buffer, $position);
  $position = $new_pos;
  ($high, $new_pos) = read_int($buffer, $position);
  $position = $new_pos;
  my $full_long = ($high<<32)+$low;
  return ($full_long, $position);
}

sub read_double
{
  my ($buffer, $position) = @_;
  return read_long($buffer, $position);
}

sub parse_scope_value
{
  my ($buffer, $position) = @_;
  my @ret = ();
  my ($code, $val, $new_pos);

  ($code, $new_pos) = read_int($buffer, $position);
  $position = $new_pos;
  if ($code == $LOCATION_CODE) {
    ($val, $new_pos) = read_int($buffer, $position);
    push @ret, "LOC_C";
    #push @ret, $val;
    my $desc = "";
    my $type = $val & 0x0F;
    if ($type == 0) {
      $desc = $desc."invalid/";
    } elsif ($type == 1) {
      $desc = $desc."normal/";
    } elsif ($type == 2) {
      $desc = $desc."oop/";
    } elsif ($type == 3) {
      $desc = $desc."int_in_long/";
    } elsif ($type == 4) {
      $desc = $desc."lng/";
    } elsif ($type == 5) {
      $desc = $desc."float_in_dbl/";
    } elsif ($type == 6) {
      $desc = $desc."dbl/";
    } elsif ($type == 7) {
      $desc = $desc."addr/";
    } elsif ($type == 8) {
      $desc = $desc."narrowoop/";
    } else {
      $desc = $desc."NA/";
    }
    if ($val & 0x10) {
      $desc = $desc."in_register/";
    } else {
      $desc = $desc."on_stack/";
    }
    my $offset = $val>>5;
    if (($val & 0x10) == 0) {
      $offset = $offset<<2;
    }
    $desc = $desc."offset$offset";
    push @ret, $desc;
    push @ret, $new_pos;
    return @ret;
  } elsif ($code == $OBJECT_ID_CODE) {
    ($val, $new_pos) = read_int($buffer, $position);
    push @ret, "OBJ_ID_C";
    push @ret, $val;
    push @ret, $new_pos;
    return @ret;
  } elsif ($code == $OBJECT_CODE) {
    ($val, $new_pos) = read_int($buffer, $position);
    push @ret, "OBJ_C";
    push @ret, $val;
    my @tmp_ret = parse_scope_value($buffer, $new_pos); 
    my $idx = 0;
    while ($idx < @tmp_ret-1) {
      push @ret, $tmp_ret[$idx];
      $idx = $idx+1;
    }
    ($val, $new_pos) = read_int($buffer, $tmp_ret[@tmp_ret-1]);
    push @ret, "Count$val";
    my $count = $val;
    $idx = 0;
    while ($idx < $count) {
      @tmp_ret = ();
      @tmp_ret = parse_scope_value($buffer, $new_pos);
      my $idx2 = 0;
      while ($idx2 < @tmp_ret-1) {
        push @ret, $tmp_ret[$idx2];
        $idx2 = $idx2+1;
      }
      $new_pos = $tmp_ret[@tmp_ret-1];
      $idx = $idx+1;
    }
    push @ret, $new_pos;
    return @ret;
  } elsif ($code == $CONSTANT_INT_CODE) {
    ($val, $new_pos) = read_int($buffer, $position);
    push @ret, "CONST_I_C";
    push @ret, $val;
    push @ret, $new_pos;
    return @ret;
  } elsif ($code == $CONSTANT_LONG_CODE) {
    ($val, $new_pos) = read_long($buffer, $position);
    push @ret, "CONST_L_C";
    push @ret, $val;
    push @ret, $new_pos;
    return @ret;
  } elsif ($code == $CONSTANT_DOUBLE_CODE) {
    ($val, $new_pos) = read_double($buffer, $position);
    push @ret, "CONST_D_C";
    push @ret, $val;
    push @ret, $new_pos;
    return @ret;
  } elsif ($code == $CONSTANT_OOP_CODE) {
    ($val, $new_pos) = read_int($buffer, $position);
    push @ret, "CONST_O_C";
    push @ret, $val;
    push @ret, $new_pos;
    return @ret;
  }
  die "BUG unknown code: $code";
}

sub parse_monitor_value
{
  my ($buffer, $position) = @_;
  my @ret = ();
  my @parse_ret = ();
  my ($basic_lock, $eliminated, $new_pos);

  ($basic_lock, $new_pos) = read_int($buffer, $position);
  $position = $new_pos;
  push @parse_ret, "basic_lock$basic_lock";
  @ret = parse_scope_value($buffer, $position);
  my $idx = 0;
  while ($idx < @ret-1) {
    push @parse_ret, $ret[$idx];
    $idx = $idx+1;
  }
  $position = $ret[@ret-1];
  ($eliminated, $new_pos) = read_b($buffer, $position);
  push @parse_ret, "eliminated$eliminated";
  push @parse_ret, $new_pos;
  return @parse_ret;
}

sub parse_dep_type
{
  my ($code) = @_;
  if ($code == 1) {
    return ("evol_method", 1);
  } elsif ($code == 2) {
    return ("leaf_type", 1);
  } elsif ($code == 3) {
    return ("abstract_with_unique_concrete_subtype", 2);
  } elsif ($code == 4) {
    return ("abstract_with_no_concrete_subtype", 1);
  } elsif ($code == 5) {
    return ("concrete_with_no_concrete_subtype", 1);
  } elsif ($code == 6) {
    return ("unique_concrete_method", 2);
  } elsif ($code == 7) {
    return ("abstract_with_exclusive_concrete_subtypes_2", 3);
  } elsif ($code == 8) {
    return ("exclusive_concrete_methods_2", 3);
  } elsif ($code == 9) {
    return ("no_finalizable_subclasses", 1);
  } elsif ($code == 10) {
    return ("call_site_target_value", 2);
  } else {
    die "Unknown dep_type: $code!";
  }
}
