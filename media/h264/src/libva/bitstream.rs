use bitstream_io::{BigEndian, BitWrite, BitWriter};
use libva::ffi;

use crate::{H264EncoderConfig, Profile};

const SLICE_TYPE_P: u8 = 0;
const SLICE_TYPE_B: u8 = 1;
const SLICE_TYPE_I: u8 = 2;

const NAL_REF_IDC_NONE: u8 = 0;
const NAL_REF_IDC_LOW: u8 = 1;
const NAL_REF_IDC_MEDIUM: u8 = 2;
const NAL_REF_IDC_HIGH: u8 = 3;

const NAL_NON_IDR: u8 = 1;
const NAL_IDR: u8 = 5;
const NAL_SPS: u8 = 7;
const NAL_PPS: u8 = 8;
const NAL_SEI: u8 = 6;

struct H264BitStreamWriter {
    buf: BitWriter<Vec<u8>, BigEndian>,
}

impl H264BitStreamWriter {
    fn new() -> Self {
        Self {
            buf: BitWriter::new(Vec::new()),
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.writer().unwrap().extend_from_slice(bytes);
    }

    fn write_bits<const BITS: u32>(&mut self, value: impl Into<u32>) {
        self.buf.write::<BITS, u32>(value.into()).unwrap();
    }

    fn write_bits_var(&mut self, bits: u32, value: u32) {
        self.buf.write_var(bits, value).unwrap();
    }

    // exponential golomb coding
    fn write_ue(&mut self, val: u32) {
        let val = val + 1;
        let len = 32 - val.leading_zeros(); // bit length of code_num

        if len > 1 {
            self.write_bits_var(len - 1, 0);
        }

        self.write_bits_var(len, val);
    }

    fn write_se(&mut self, val: i32) {
        let val = if val <= 0 { -2 * val } else { 2 * val - 1 };

        self.write_ue(val.cast_unsigned());
    }

    fn write_nal_start_code_prefix(&mut self) {
        self.write_bytes(&[0, 0, 0, 1]);
    }

    fn write_nal_header(&mut self, nal_ref_idc: u8, nal_unit_type: u8) {
        // forbidden zero bit
        self.write_bits::<1>(0u32);
        self.write_bits::<2>(nal_ref_idc);
        self.write_bits::<5>(nal_unit_type);
    }

    fn rbsp_trailing_bits(&mut self) {
        self.write_bits::<1>(1u8);
        self.buf.byte_align().unwrap();
    }
}

/// Returns the encoded buffer with the bit length
pub(super) fn write_sps_rbsp(
    encode_config: &H264EncoderConfig,
    seq_param: &ffi::VAEncSequenceParameterBufferH264,
) -> Vec<u8> {
    let seq_fields = unsafe { &seq_param.seq_fields.bits };

    let mut writer = H264BitStreamWriter::new();

    writer.write_nal_start_code_prefix();
    writer.write_nal_header(NAL_REF_IDC_HIGH, NAL_SPS);

    writer.write_bits::<8>(encode_config.profile.profile_idc());
    writer.write_bits::<8>(encode_config.profile.profile_iop());
    writer.write_bits::<8>(encode_config.level.level_idc());

    writer.write_ue(seq_param.seq_parameter_set_id as u32);

    if matches!(
        encode_config.profile,
        Profile::High
            | Profile::High10
            | Profile::High422
            | Profile::High444Intra
            | Profile::High444Predictive
    ) {
        writer.write_ue(1); // TODO: YUV420 - THIS IS WRONG for every non-yuv420 entrypoint
        // TODO: if chroma_format_idc == 3 put separate_colour_plane_flag
        writer.write_ue(0); // bit_depth_luma_minus8 - TODO: also wrong, for High10
        writer.write_ue(0); // bit_depth_chroma_minus8 - TODO: also wrong, for High10
        writer.write_bits::<1>(0u32); // qpprime_y_zero_transform_bypass_flag
        writer.write_bits::<1>(0u32); // seq_scaling_matrix_present_flag
    }

    writer.write_ue(seq_fields.log2_max_frame_num_minus4());
    writer.write_ue(seq_fields.pic_order_cnt_type());

    if seq_fields.pic_order_cnt_type() == 0 {
        writer.write_ue(seq_fields.log2_max_pic_order_cnt_lsb_minus4());
    } else {
        panic!(
            "unimplemented pic_order_cnt_type {}",
            seq_fields.pic_order_cnt_type()
        );
    }

    writer.write_ue(seq_param.max_num_ref_frames);
    writer.write_bits::<1>(0u8); /* gaps_in_frame_num_value_allowed_flag */

    writer.write_ue(seq_param.picture_width_in_mbs as u32 - 1);
    writer.write_ue(seq_param.picture_height_in_mbs as u32 - 1);
    writer.write_bits::<1>(seq_fields.frame_mbs_only_flag());

    assert_ne!(
        seq_fields.frame_mbs_only_flag(),
        0,
        "Interlaced encoding not supported"
    );

    writer.write_bits::<1>(seq_fields.direct_8x8_inference_flag());
    writer.write_bits::<1>(seq_param.frame_cropping_flag);

    if seq_param.frame_cropping_flag != 0 {
        writer.write_ue(seq_param.frame_crop_left_offset);
        writer.write_ue(seq_param.frame_crop_right_offset);
        writer.write_ue(seq_param.frame_crop_top_offset);
        writer.write_ue(seq_param.frame_crop_bottom_offset);
    }

    // TODO: vui parameters, currently always setting it to 0
    writer.write_bits::<1>(0u32);

    writer.rbsp_trailing_bits();

    writer.buf.into_writer()
}

/// Returns the encoded buffer with the bit length
pub(super) fn write_pps_rbsp(pic_param: &ffi::VAEncPictureParameterBufferH264) -> Vec<u8> {
    let pic_fields = unsafe { &pic_param.pic_fields.bits };

    let mut writer = H264BitStreamWriter::new();

    writer.write_nal_start_code_prefix();
    writer.write_nal_header(NAL_REF_IDC_HIGH, NAL_PPS);

    //     pic_parameter_set_id  ue(v)
    writer.write_ue(pic_param.pic_parameter_set_id.into());
    //     seq_parameter_set_id  ue(v)
    writer.write_ue(pic_param.seq_parameter_set_id.into());

    //     entropy_coding_mode_flag u(1)
    writer.write_bits::<1>(pic_fields.entropy_coding_mode_flag());

    //     bottom_field_pic_order_in_frame_present_flag  u(1)
    writer.write_bits::<1>(pic_fields.pic_order_present_flag());

    //     num_slice_groups_minus1  ue(v)
    writer.write_ue(0);

    //     if ( num_slice_groups_minus1 > 0 ) {
    //         slice_group_map_type  ue(v)
    //         if ( slice_group_map_type == 0 )
    //         for( iGroup = 0; iGroup <= num_slice_groups_minus1; iGroup++ )
    //         run_length_minus1[ iGroup ]  ue(v)
    //         else if ( slice_group_map_type == 2 )
    //         for( iGroup = 0; iGroup < num_slice_groups_minus1; iGroup++ ) {
    //             top_left[ iGroup ]  ue(v)
    //             bottom_right[ iGroup ]  ue(v)
    //         }
    //         else if ( slice_group_map_type == 3 | |
    //             slice_group_map_type == 4 | |
    //             slice_group_map_type == 5 ) {
    //             slice_group_change_direction_flag  u(1)
    //             slice_group_change_rate_minus1  ue(v)
    //         } else if ( slice_group_map_type == 6 ) {
    //             pic_size_in_map_units_minus1  ue(v)
    //             for( i = 0; i <= pic_size_in_map_units_minus1; i++ )
    //             slice_group_id[ i ]  u(v)
    //         }
    //     }

    //     num_ref_idx_l0_default_active_minus1  ue(v)
    writer.write_ue(pic_param.num_ref_idx_l0_active_minus1.into());
    //     num_ref_idx_l1_default_active_minus1  ue(v)
    writer.write_ue(pic_param.num_ref_idx_l1_active_minus1.into());

    //     weighted_pred_flag  u(1)
    writer.write_bits::<1>(pic_fields.weighted_pred_flag());
    //     weighted_bipred_idc  u(2)
    writer.write_bits::<2>(pic_fields.weighted_bipred_idc());

    //     pic_init_qp_minus26  se(v)
    writer.write_se(pic_param.pic_init_qp as i32 - 26); // pic_init_qp_minus26
    //     pic_init_qs_minus26  se(v)
    writer.write_se(0);
    //     chroma_qp_index_offset  se(v)
    writer.write_se(0);

    //     deblocking_filter_control_present_flag  u(1)
    writer.write_bits::<1>(pic_fields.deblocking_filter_control_present_flag());
    //     constrained_intra_pred_flag  u(1)
    writer.write_bits::<1>(pic_fields.constrained_intra_pred_flag());
    //     redundant_pic_cnt_present_flag 1 u(1)
    writer.write_bits::<1>(pic_fields.redundant_pic_cnt_present_flag());

    //     if ( more_rbsp_data( ) ) { // true

    //         transform_8x8_mode_flag 1 u(1)
    writer.write_bits::<1>(pic_fields.transform_8x8_mode_flag());

    //         pic_scaling_matrix_present_flag 1 u(1)
    writer.write_bits::<1>(pic_fields.pic_scaling_matrix_present_flag());

    //          if ( pic_scaling_matrix_present_flag )
    //              for( i = 0;
    //                   i < 6 + ( ( chroma_format_idc != 3 ) ? 2 : 6 ) * transform_8x8_mode_flag;
    //                   i++ ) {
    //                  pic_scaling_list_present_flag[ i ] 1 u(1)
    //                  if ( pic_scaling_list_present_flag[ i ] )
    //                      if ( i < 6 )
    //                          scaling_list( ScalingList4x4[ i ], 16, UseDefaultScalingMatrix4x4Flag[ i ] )
    //                      else
    //                           scaling_list( ScalingList8x8[ i − 6 ], 64, UseDefaultScalingMatrix8x8Flag[ i − 6 ] )
    //             }
    if pic_fields.pic_scaling_matrix_present_flag() != 0 {
        panic!("pic_scaling_matrix_present_flag is not implemented")
    }

    //         second_chroma_qp_index_offset 1 se(v)
    writer.write_se(pic_param.second_chroma_qp_index_offset.into());

    //     } // more rbsp_data

    writer.rbsp_trailing_bits();

    writer.buf.into_writer()
}

/// Returns the encoded buffer with the bit length
pub(super) fn write_slice_header(
    seq_param: &ffi::VAEncSequenceParameterBufferH264,
    pic_param: &ffi::VAEncPictureParameterBufferH264,
    slice_param: &ffi::VAEncSliceParameterBufferH264,
) -> Vec<u8> {
    let seq_fields = unsafe { &seq_param.seq_fields.bits };
    let pic_fields = unsafe { &pic_param.pic_fields.bits };

    let is_idr = pic_fields.idr_pic_flag() != 0;
    let is_ref = pic_fields.reference_pic_flag() != 0;

    let (nal_ref_idc, nal_unit_type) = match slice_param.slice_type {
        SLICE_TYPE_I => (NAL_REF_IDC_HIGH, if is_idr { NAL_IDR } else { NAL_NON_IDR }),
        SLICE_TYPE_P => (NAL_REF_IDC_MEDIUM, NAL_NON_IDR),
        SLICE_TYPE_B => (
            if is_ref {
                NAL_REF_IDC_LOW
            } else {
                NAL_REF_IDC_NONE
            },
            NAL_NON_IDR,
        ),
        _ => panic!("Unknown slice_type: {}", slice_param.slice_type),
    };

    let mut writer = H264BitStreamWriter::new();
    writer.write_nal_start_code_prefix();
    writer.write_nal_header(nal_ref_idc, nal_unit_type);

    //     first_mb_in_slice  ue(v))
    writer.write_ue(slice_param.macroblock_address);
    //     slice_type  ue(v))
    writer.write_ue(slice_param.slice_type.into());
    //     pic_parameter_set_id  ue(v))
    writer.write_ue(slice_param.pic_parameter_set_id.into());

    //     if ( separate_colour_plane_flag == 1 )
    //         colour_plane_id  u(2)

    //     frame_num  u(v)
    writer.write_bits_var(
        seq_fields.log2_max_frame_num_minus4() + 4,
        pic_param.frame_num as u32,
    );

    //     if ( !frame_mbs_only_flag ) {
    //         field_pic_flag  u(1)
    //         if ( field_pic_flag )
    //             bottom_field_flag  u(1)
    //     }
    if seq_fields.frame_mbs_only_flag() == 0 {
        panic!("Interlaced encoding is not supported");
    }

    //     if ( IdrPicFlag )
    //         idr_pic_id  ue(v)
    if pic_fields.idr_pic_flag() != 0 {
        writer.write_ue(slice_param.idr_pic_id.into());
    }

    //     if ( pic_order_cnt_type == 0 ) {
    //             pic_order_cnt_lsb  u(v)
    //         if ( bottom_field_pic_order_in_frame_present_flag && !field_pic_flag )
    //             delta_pic_order_cnt_bottom  se(v)
    //     }
    //     if ( pic_order_cnt_type == 1 && !delta_pic_order_always_zero_flag ) {
    //         delta_pic_order_cnt[ 0 ]  se(v)
    //         if ( bottom_field_pic_order_in_frame_present_flag && !field_pic_flag )
    //             delta_pic_order_cnt[ 1 ]  se(v)
    //     }
    if seq_fields.pic_order_cnt_type() == 0 {
        writer.write_bits_var(
            seq_fields.log2_max_pic_order_cnt_lsb_minus4() + 4,
            pic_param.CurrPic.TopFieldOrderCnt as u32,
        );
    } else {
        panic!("only pic_order_cnt_type 0 is implemented",);
    }

    //     if ( redundant_pic_cnt_present_flag )
    //         redundant_pic_cnt  ue(v))

    //     if ( slice_type == B )
    //         direct_spatial_mv_pred_flag  u(1)
    if slice_param.slice_type == SLICE_TYPE_B {
        writer.write_bits::<1>(slice_param.direct_spatial_mv_pred_flag);
    }

    //     if ( slice_type == P | | slice_type == SP | | slice_type == B ) {
    //         num_ref_idx_active_override_flag  u(1)
    //         if ( num_ref_idx_active_override_flag ) {
    //             num_ref_idx_l0_active_minus1  ue(v))
    //             if ( slice_type == B )
    //                 num_ref_idx_l1_active_minus1  ue(v))
    //         }
    //     }
    if matches!(slice_param.slice_type, SLICE_TYPE_P | SLICE_TYPE_B) {
        writer.write_bits::<1>(slice_param.num_ref_idx_active_override_flag);

        if slice_param.num_ref_idx_active_override_flag != 0 {
            writer.write_ue(slice_param.num_ref_idx_l0_active_minus1.into());

            if slice_param.slice_type == SLICE_TYPE_B {
                writer.write_ue(slice_param.num_ref_idx_l1_active_minus1.into());
            }
        }
    }

    //     if ( nal_unit_type == 20 | | nal_unit_type == 21 )
    //         ref_pic_list_mvc_modification( ) /* specified in Annex G */ 2
    //     else
    //         ref_pic_list_modification( )
    // ref_pic_list_modification() and ref_pic_list_mvc_modification() are treated the same here
    // see H.264 2024.08 G.7.3.3.1.1
    if slice_param.slice_type % 5 != 2 && slice_param.slice_type % 5 != 4 {
        // ref_pic_list_modification_flag_l0 u(1)
        writer.write_bits::<1>(0u32);
    }
    if slice_param.slice_type % 5 == 1 {
        // ref_pic_list_modification_flag_l1 u(1)
        writer.write_bits::<1>(0u32);
    }

    //     if ( ( weighted_pred_flag && ( slice_type == P | | slice_type == SP ) ) | |
    //         ( weighted_bipred_idc == 1 && slice_type == B ) )
    //         pred_weight_table( )

    //     if ( nal_ref_idc != 0 )
    //         dec_ref_pic_marking( )
    if nal_ref_idc != 0 {
        // dec_ref_pic_marking( ) {
        //     if ( IdrPicFlag ) {
        //         no_output_of_prior_pics_flag  u(1)
        //         long_term_reference_flag  u(1)
        //     } else {
        //         adaptive_ref_pic_marking_mode_flag  u(1)
        //         if ( adaptive_ref_pic_marking_mode_flag )
        //             do {
        //                 memory_management_control_operation  ue(v)
        //                 if ( memory_management_control_operation == 1 | |
        //                     memory_management_control_operation == 3 )
        //                     difference_of_pic_nums_minus1  ue(v)
        //                 if (memory_management_control_operation == 2 )
        //                     long_term_pic_num  ue(v)
        //                 if ( memory_management_control_operation == 3 | |
        //                     memory_management_control_operation == 6 )
        //                 long_term_frame_idx  ue(v)
        //                 if ( memory_management_control_operation == 4 )
        //                     max_long_term_frame_idx_plus1  ue(v)
        //             } while( memory_management_control_operation != 0 )
        //     }
        // }

        if is_idr {
            writer.write_bits::<1>(0u32);
            writer.write_bits::<1>(0u32);
        } else {
            writer.write_bits::<1>(0u32);
        }
    }

    //     if ( entropy_coding_mode_flag && slice_type != I && slice_type != SI )
    //         cabac_init_idc  ue(v))
    if pic_fields.entropy_coding_mode_flag() != 0 && slice_param.slice_type != SLICE_TYPE_I {
        writer.write_ue(slice_param.cabac_init_idc.into());
    }

    //     slice_qp_delta  se(v)
    writer.write_se(slice_param.slice_qp_delta.into());

    //     if ( slice_type == SP | | slice_type == SI ) {
    //         if ( slice_type == SP )
    //         sp_for_switch_flag  u(1)
    //         slice_qs_delta  se(v)
    //     }

    //     if ( deblocking_filter_control_present_flag ) {
    //         disable_deblocking_filter_idc  ue(v))
    //         if ( disable_deblocking_filter_idc != 1 ) {
    //             slice_alpha_c0_offset_div2  se(v)
    //             slice_beta_offset_div2  se(v)
    //         }
    //     }
    if pic_fields.deblocking_filter_control_present_flag() != 0 {
        writer.write_ue(slice_param.disable_deblocking_filter_idc.into());

        if slice_param.disable_deblocking_filter_idc != 1 {
            writer.write_se(slice_param.slice_alpha_c0_offset_div2.into());
            writer.write_se(slice_param.slice_beta_offset_div2.into());
        }
    }

    //     if ( num_slice_groups_minus1 > 0 &&
    //         slice_group_map_type >= 3 && slice_group_map_type <= 5)
    //         slice_group_change_cycle  u(v)

    // Copied from libva:
    if pic_fields.entropy_coding_mode_flag() != 0 {
        while !writer.buf.byte_aligned() {
            writer.write_bits::<1>(1u32);
        }
    }

    writer.buf.byte_align().unwrap();
    writer.buf.into_writer()
}
