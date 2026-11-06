// Parametric enclosure for ESP8266 dev boards (NodeMCU / D1 mini class).
// Same geometry as esp8266-enclosure.py; edit the numbers, render, print.
//
//   board_w = width across the two header rows
//   board_l = length from the USB end to the antenna end
//
// The board drops in from the top, the side ribs catch the header strips,
// the end wall leaves a slot for the USB plug, and the antenna end is left
// open so nothing sits next to the radio.

board_w      = 30;    // mm
board_l      = 58;    // mm
pcb_t        = 1.6;
wall         = 2;
floor_t      = 2;
side_clear   = 1;
wall_h       = 18;
antenna_open = 13;
rail_h       = 2;
rail_w       = 3;
rail_inset   = 2;
rib_h        = 3;
rib_interference = 0.2;
usb_cut_w    = 16;
usb_slot_h   = 9;
vent_count   = 4;
vent_w       = 2;
vent_h       = 6;
vent_z       = 9;
vent_start   = 8;
vent_pitch   = 6;

half      = board_w / 2;
in_half   = half + side_clear;
out_half  = in_half + wall;
side_end  = board_l - antenna_open;
rail_top  = floor_t + rail_h;
pcb_top   = rail_top + pcb_t;
slot_top  = floor_t + usb_slot_h;

module side_wall(s) {
    wall_x = [s * in_half, s * out_half];
    translate([min(wall_x), -wall, 0])
        cube([abs(wall_x[1] - wall_x[0]), side_end + wall, wall_h - floor_t]);
    for (i = [0 : vent_count - 1])
        translate([min(wall_x), vent_start + i * vent_pitch, vent_z])
            cube([abs(wall_x[1] - wall_x[0]), vent_w, wall_h - vent_z]);
    translate([min(wall_x), -wall, vent_z + vent_h])
        cube([abs(wall_x[1] - wall_x[0]), side_end + wall, wall_h - vent_z - vent_h]);
    translate([min(wall_x), -wall, floor_t])
        cube([abs(wall_x[1] - wall_x[0]), side_end + wall, vent_z - floor_t]);
}

module rail(s) {
    x0 = s * (half - rail_inset);
    x1 = s * (half - rail_inset - rail_w);
    translate([min(x0, x1), 0, floor_t])
        cube([rail_w, board_l, rail_h]);
}

module rib(s) {
    x_out = s * in_half;
    x_in  = s * (in_half - side_clear - rib_interference);
    x_in2 = s * (in_half - side_clear - rib_interference + 0.6);
    translate([min(x_out, x_in), 0, pcb_top])
        cube([abs(x_out - x_in), side_end, rib_h * 0.45]);
    translate([min(x_out, x_in2), 0, pcb_top + rib_h * 0.45])
        cube([abs(x_out - x_in2), side_end, rib_h * 0.55]);
}

module enclosure() {
    translate([-out_half, -wall, 0])
        cube([out_half * 2, board_l + wall, floor_t]);
    for (s = [-1, 1]) {
        side_wall(s);
        rail(s);
        rib(s);
    }
    translate([-in_half, -wall, floor_t])
        cube([in_half - usb_cut_w / 2, wall, wall_h - floor_t]);
    translate([usb_cut_w / 2, -wall, floor_t])
        cube([in_half - usb_cut_w / 2, wall, wall_h - floor_t]);
    translate([-usb_cut_w / 2, -wall, slot_top])
        cube([usb_cut_w, wall, wall_h - slot_top]);
}

enclosure();
