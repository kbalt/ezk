use std::ptr;

use ffmpeg::{
    codec::{traits::Encoder, Context, Id},
    format::Pixel,
    Dictionary, Rational,
};

#[test]
fn test() {
    let mtu = 1500;

    ffmpeg::init().unwrap();

    unsafe {
        let mut device_ctx = ptr::null_mut();

        let mut buf = vec![0u8; 1024];
        println!(
            "{}",
            ffmpeg::sys::av_strerror(-542398533, buf.as_mut_ptr().cast(), 1024)
        );
        println!("{:?}", String::from_utf8_lossy(&buf));

        assert_eq!(
            ffmpeg::sys::av_hwdevice_ctx_create(
                &mut device_ctx,
                ffmpeg::ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI,
                ptr::null(),
                ptr::null_mut(),
                0,
            ),
            0
        );

        let codec = ffmpeg::codec::encoder::find_by_name("h264_vaapi").unwrap();
        let mut ctx = Context::new_with_codec(codec).encoder().video().unwrap();
        ctx.set_format(Pixel::VAAPI);
        ctx.set_width(1920);
        ctx.set_height(1080);
        let hwframe = ffmpeg::sys::av_hwframe_ctx_alloc(device_ctx);
        let hwframe_data = (*hwframe).data.cast::<ffmpeg::sys::AVHWFramesContext>();

        (*hwframe_data).format = ffmpeg::sys::AVPixelFormat::AV_PIX_FMT_VAAPI;
        (*hwframe_data).sw_format = ffmpeg::sys::AVPixelFormat::AV_PIX_FMT_NV12;
        (*hwframe_data).width = 1920;
        (*hwframe_data).height = 1920;
        (*hwframe_data).initial_pool_size = 1920;
        assert_eq!(ffmpeg::sys::av_hwframe_ctx_init(hwframe), 0);
    }
    // for device in ffmpeg::device::input::video() {
    //     println!("Device: {} - {:?}", device.name(), device.description());
    //     println!("\tExtensions: {:?}", device.extensions());
    //     println!("\tMime Types: {:?}", device.mime_types());
    //     // https://ffmpeg.org/doxygen/5.1/vaapi_encode_8c-example.html
    // }

    // let vaapi_frame = ffmpeg::frame::Video::new(Pixel::YUV420P, 1920, 1080);
    // let c = vaapi_frame.converter(Pixel::VAAPI).unwrap();
    // // https://github.com/FFmpeg/FFmpeg/blob/43be8d07281caca2e88bfd8ee2333633e1fb1a13/libavcodec/libopenh264enc.c#L70
    // // https://github.com/FFmpeg/FFmpeg/blob/43be8d07281caca2e88bfd8ee2333633e1fb1a13/libavcodec/libx264.c#L1552

    // let mut encoder = Context::new_with_codec(x).encoder().video().unwrap();

    // encoder.set_time_base(Rational::new(1, 1000));
    // encoder.set_format(Pixel::VAAPI);
    // encoder.set_width(1920);
    // encoder.set_height(1080);
    // encoder
    //     .open_with(Dictionary::from_iter([
    //         ("allow_skip_frames", "true"),
    //         ("device", "/dev/dri/renderD128"), // ("max_nal_size", mtu.to_string().as_str()),
    //     ]))
    //     .unwrap();

    // encoder.set_dia_size(value);
}
