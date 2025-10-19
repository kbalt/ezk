@group(0) @binding(0) var input_image: texture_2d<f32>;
@group(0) @binding(1) var input_sampler: sampler;
@group(0) @binding(2) var output_y: texture_storage_2d<r8unorm, write>;
@group(0) @binding(3) var output_uv: texture_storage_2d<rg8unorm, write>;
@group(0) @binding(4) var<uniform> colorspace: vec3<f32>;
@group(0) @binding(5) var<uniform> scale: vec2<f32>;

fn rgb_to_yuv(rgb: vec3<f32>) -> vec3<f32> {
    let kr = colorspace.r;
    let kg = colorspace.g;
    let kb = colorspace.b;

    let y = kr * rgb.r + kg * rgb.g + kb * rgb.b;
    let u = (rgb.b - y) / (2.0 * (1.0 - kb)) + 0.5;
    let v = (rgb.r - y) / (2.0 * (1.0 - kr)) + 0.5;

    return vec3<f32>(y, u, v);
}

/// Write out U & V into the UV plane
fn write_uv(
    pos: vec2<u32>,
    yuv00: vec3<f32>,
    yuv01: vec3<f32>,
    yuv10: vec3<f32>,
    yuv11: vec3<f32>,
) {
    let u = (yuv00.y + yuv10.y + yuv01.y + yuv11.y) * 0.25;
    let v = (yuv00.z + yuv10.z + yuv01.z + yuv11.z) * 0.25;

    textureStore(output_uv, pos / 2u, vec4<f32>(u, v, 0.0, 0.0));
}

fn to_logical(physical_pos: vec2<u32>) -> vec2<f32> {
    return vec2<f32>(
        f32(physical_pos.x) * scale.x,
        f32(physical_pos.y) * scale.y,
    );
}

fn sample_input(pos: vec2<f32>) -> vec4<f32> {
    return textureSampleLevel(input_image, input_sampler, pos, 0.0);
}

@compute @workgroup_size(16, 16, 1)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let physical_pos = global_id.xy;
    let image_size = textureDimensions(output_y);

    if physical_pos.x >= image_size.x || physical_pos.y >= image_size.y {
        return;
    }

    let yuv00_pos = to_logical(physical_pos);

    let yuv00 = rgb_to_yuv(sample_input(yuv00_pos).rgb);

    textureStore(output_y, physical_pos, vec4<f32>(yuv00.x, 0.0, 0.0, 0.0));

    if (physical_pos.x % 2u) == 0 && (physical_pos.y % 2u) == 0 {
        let yuv10_pos = to_logical(physical_pos + vec2<u32>(1, 0));
        let yuv01_pos = to_logical(physical_pos + vec2<u32>(0, 1));
        let yuv11_pos = to_logical(physical_pos + vec2<u32>(1, 1));

        let yuv10 = rgb_to_yuv(vec3<f32>(sample_input(yuv10_pos).rgb));
        let yuv01 = rgb_to_yuv(vec3<f32>(sample_input(yuv01_pos).rgb));
        let yuv11 = rgb_to_yuv(vec3<f32>(sample_input(yuv11_pos).rgb));

        write_uv(physical_pos, yuv00, yuv01, yuv10, yuv11);
    }
}
