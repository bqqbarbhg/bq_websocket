
#define SOKOL_IMPL
#define SOKOL_GL_IMPL

#if defined(_WIN32)
	#define SOKOL_D3D11
#else
	#define SOKOL_GLES2
#endif

#include "sokol_app.h"
#include "sokol_args.h"
#include "sokol_gfx.h"
#include "sokol_gl.h"
#include "sokol_time.h"

#define SAMPLE_COUNT (4)

static sgl_pipeline pipeline;
static bool key_state[SAPP_MAX_KEYCODES];
static uint64_t prev_time;

void game_init();
void game_frame(float dt);
void game_cleanup();

bool key_down(sapp_keycode code)
{
    return key_state[code];
}

static void init(void) {
    sg_setup(&(sg_desc){
        .gl_force_gles2 = sapp_gles2(),
        .mtl_device = sapp_metal_get_device(),
        .mtl_renderpass_descriptor_cb = sapp_metal_get_renderpass_descriptor,
        .mtl_drawable_cb = sapp_metal_get_drawable,
        .d3d11_device = sapp_d3d11_get_device(),
        .d3d11_device_context = sapp_d3d11_get_device_context(),
        .d3d11_render_target_view_cb = sapp_d3d11_get_render_target_view,
        .d3d11_depth_stencil_view_cb = sapp_d3d11_get_depth_stencil_view,
    });

    /* setup sokol-gl */
    sgl_setup(&(sgl_desc_t){
        .sample_count = SAMPLE_COUNT
    });

    pipeline = sgl_make_pipeline(&(sg_pipeline_desc){
        .depth_stencil = {
            .depth_write_enabled = true,
            .depth_compare_func = SG_COMPAREFUNC_LESS_EQUAL,
        },
        .rasterizer = {
            .cull_mode = SG_CULLMODE_BACK
        }
    });

    stm_setup();

    game_init();
}
static void frame(void) {
    sgl_load_pipeline(pipeline);

    float dt = (float)stm_sec(stm_laptime(&prev_time));
    float min_dt = 1.0f / 1000.0f;
    float max_dt = 1.0f / 15.0f;
    if (dt > max_dt) dt = max_dt;
    if (dt < min_dt) dt = min_dt;
    game_frame(dt);

    sg_pass_action action = { 0 };
    action.colors[0].action = SG_ACTION_CLEAR;
    sg_begin_default_pass(&action, sapp_width(), sapp_height());
    sgl_draw();
    sg_end_pass();
    sg_commit();
}

static void event(const sapp_event *e)
{
    if (e->type == SAPP_EVENTTYPE_KEY_DOWN) {
        key_state[e->key_code] = true;
    } else if (e->type == SAPP_EVENTTYPE_KEY_UP) {
        key_state[e->key_code] = false;
    }
}

static void cleanup(void) {
    game_cleanup();

    sgl_shutdown();
    sg_shutdown();
}

sapp_desc sokol_main(int argc, char* argv[]) {
    {
		sargs_setup(&(sargs_desc) {
            .argc = argc,
            .argv = argv,
        });
    }

    return (sapp_desc){
        .init_cb = init,
        .frame_cb = frame,
        .cleanup_cb = cleanup,
        .event_cb = event,
        .width = 800,
        .height = 600,
        .sample_count = SAMPLE_COUNT,
        .gl_force_gles2 = true,
        .window_title = "BQWS Game",
    };
}
