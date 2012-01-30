#pragma once


enum parser_flags {
	parser_flag_unknown				  = 0,
    parser_flag_chunked               = 1 << 0,
    parser_flag_connection_keep_alive = 1 << 1,
    parser_flag_connection_close      = 1 << 2,
    parser_flag_trailing              = 1 << 3,
	parser_flag_connection_upgrade    = 1 << 4,	
};