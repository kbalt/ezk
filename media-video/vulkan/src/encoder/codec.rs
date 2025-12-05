use crate::{VideoSessionParameters, VulkanError};
use ash::vk;
use std::{ffi::CStr, fmt};

pub trait VulkanEncCodec {
    const ENCODE_OPERATION: vk::VideoCodecOperationFlagsKHR;
    const EXTENSION: &'static CStr;
    type ProfileInfo<'a>: vk::ExtendsVideoProfileInfoKHR + fmt::Debug + Copy;
    type Capabilities<'a>: vk::ExtendsVideoCapabilitiesKHR + Default + fmt::Debug + Copy;
    type ParametersCreateInfo<'a>: vk::ExtendsVideoSessionParametersCreateInfoKHR
        + fmt::Debug
        + Copy;
    type ParametersAddInfo<'a>: vk::ExtendsVideoSessionParametersUpdateInfoKHR + fmt::Debug + Copy;

    type StdReferenceInfo: fmt::Debug + Copy;
    type DpbSlotInfo<'a>: vk::ExtendsVideoReferenceSlotInfoKHR + fmt::Debug + Copy;

    fn slot_info_from_std(std_reference_info: &Self::StdReferenceInfo) -> Self::DpbSlotInfo<'_>;

    type PictureInfo<'a>: vk::ExtendsVideoEncodeInfoKHR + fmt::Debug + Copy;

    type RateControlInfo<'a>: vk::ExtendsVideoBeginCodingInfoKHR
        + vk::ExtendsVideoCodingControlInfoKHR
        + fmt::Debug
        + Copy;
    type RateControlLayerInfo<'a>: fmt::Debug
        + vk::ExtendsVideoEncodeRateControlLayerInfoKHR
        + fmt::Debug
        + Copy;

    #[allow(private_interfaces)]
    fn get_encoded_video_session_parameters(
        video_session_parameters: &VideoSessionParameters,
    ) -> Result<Vec<u8>, VulkanError>;
}

#[derive(Debug)]
pub struct H264;

impl VulkanEncCodec for H264 {
    const ENCODE_OPERATION: vk::VideoCodecOperationFlagsKHR =
        vk::VideoCodecOperationFlagsKHR::ENCODE_H264;
    const EXTENSION: &'static CStr = ash::khr::video_encode_h264::NAME;
    type ProfileInfo<'a> = vk::VideoEncodeH264ProfileInfoKHR<'a>;
    type Capabilities<'a> = vk::VideoEncodeH264CapabilitiesKHR<'a>;
    type ParametersCreateInfo<'a> = vk::VideoEncodeH264SessionParametersCreateInfoKHR<'a>;
    type ParametersAddInfo<'a> = vk::VideoEncodeH264SessionParametersAddInfoKHR<'a>;

    type StdReferenceInfo = vk::native::StdVideoEncodeH264ReferenceInfo;
    type DpbSlotInfo<'a> = vk::VideoEncodeH264DpbSlotInfoKHR<'a>;

    fn slot_info_from_std(std_reference_info: &Self::StdReferenceInfo) -> Self::DpbSlotInfo<'_> {
        vk::VideoEncodeH264DpbSlotInfoKHR::default().std_reference_info(std_reference_info)
    }

    type PictureInfo<'a> = vk::VideoEncodeH264PictureInfoKHR<'a>;

    type RateControlInfo<'a> = vk::VideoEncodeH264RateControlInfoKHR<'a>;
    type RateControlLayerInfo<'a> = vk::VideoEncodeH264RateControlLayerInfoKHR<'a>;

    #[allow(private_interfaces)]
    fn get_encoded_video_session_parameters(
        video_session_parameters: &VideoSessionParameters,
    ) -> Result<Vec<u8>, VulkanError> {
        let mut info = vk::VideoEncodeH264SessionParametersGetInfoKHR::default()
            .write_std_sps(true)
            .write_std_pps(true);

        unsafe { video_session_parameters.get_encoded_video_session_parameters(&mut info) }
    }
}

#[derive(Debug)]
pub struct H265;

impl VulkanEncCodec for H265 {
    const ENCODE_OPERATION: vk::VideoCodecOperationFlagsKHR =
        vk::VideoCodecOperationFlagsKHR::ENCODE_H265;
    const EXTENSION: &'static CStr = ash::khr::video_encode_h265::NAME;
    type ProfileInfo<'a> = vk::VideoEncodeH265ProfileInfoKHR<'a>;
    type Capabilities<'a> = vk::VideoEncodeH265CapabilitiesKHR<'a>;
    type ParametersCreateInfo<'a> = vk::VideoEncodeH265SessionParametersCreateInfoKHR<'a>;
    type ParametersAddInfo<'a> = vk::VideoEncodeH265SessionParametersAddInfoKHR<'a>;
    type DpbSlotInfo<'a> = vk::VideoEncodeH265DpbSlotInfoKHR<'a>;

    type StdReferenceInfo = vk::native::StdVideoEncodeH265ReferenceInfo;

    fn slot_info_from_std(std_reference_info: &Self::StdReferenceInfo) -> Self::DpbSlotInfo<'_> {
        vk::VideoEncodeH265DpbSlotInfoKHR::default().std_reference_info(std_reference_info)
    }

    type PictureInfo<'a> = vk::VideoEncodeH265PictureInfoKHR<'a>;

    type RateControlInfo<'a> = vk::VideoEncodeH265RateControlInfoKHR<'a>;
    type RateControlLayerInfo<'a> = vk::VideoEncodeH265RateControlLayerInfoKHR<'a>;

    #[allow(private_interfaces)]
    fn get_encoded_video_session_parameters(
        video_session_parameters: &VideoSessionParameters,
    ) -> Result<Vec<u8>, VulkanError> {
        let mut info = vk::VideoEncodeH265SessionParametersGetInfoKHR::default()
            .write_std_sps(true)
            .write_std_pps(true)
            .write_std_vps(true);

        unsafe { video_session_parameters.get_encoded_video_session_parameters(&mut info) }
    }
}
