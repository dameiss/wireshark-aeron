/* packet-aeron-hsd.c
 * Example base for integrating custom payload dissectors into the
 * Aeron dissectors.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#ifndef HAVE_INET_ATON
    #include <wsutil/inet_aton.h>
#endif

static int proto_aerondata = -1;
static int ett_aerondata = -1;
static int hf_aerondata_magic = -1;
static int hf_aerondata_checksum = -1;
static int hf_aerondata_sqn = -1;
static int hf_aerondata_data = -1;

#define O_AERONDATA_MAGIC 0
#define O_AERONDATA_CHECKSUM 4
#define O_AERONDATA_SQN 8
#define O_AERONDATA_DATA 12
#define AERONDATA_MAGIC 0x0dd01221

static gboolean test_aerondata_packet(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree _U_)
{
    /*
        A test function is useful, especially if you have several different payload
        formats in use, and/or the format detection logic is complex or involved.
        Return TRUE if we understand this payload and want to dissect it.
        Otherwise return FALSE.
    */

    /*
        PublisherTool, by default, sends messages which contain a magic number. So check for it.
    */

    if (tvb_reported_length_remaining(tvb, 0) >= O_AERONDATA_DATA)
    {
        guint32 magic = tvb_get_letohl(tvb, O_AERONDATA_MAGIC);
        if (magic == AERONDATA_MAGIC)
        {
            return (TRUE);
        }
    }
    /* Not one of ours. */
    return (FALSE);
}

/*
 * dissect_aerondata - The dissector for Aeron message payloads
 */

gboolean dissect_aerondata(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * user_data _U_)
{
    proto_tree * data_tree = NULL;
    proto_item * ti = NULL;

    /*
        A heuristic (sub)dissector must return TRUE if it handled the packet, or
        FALSE if it did not. Of course, implicit in this is that if you indicate you
        DID handle the packet, you darn well better have actually handled it.
        Returning TRUE tells the heuristic subdissector (HSD) handling code to not look
        at any other HSDs. Obviously, returning FALSE causes the next HSD (if any) to be
        tried.
    */
    
    /* First thing - see if this is a payload we can or want to handle. */
    if (!test_aerondata_packet(tvb, pinfo, tree))
    {
        return (FALSE);
    }

    /* Don't change the Protocol column, since upper-level dissectors have set this. */

    /*
        col_clear() will clear the Info column. But, there may be something useful there already.
        So rather than clearing it, we can append a string to the column. Below, we use
        col_append_sep_str(), which appends a separator (which defaults to ", ") to the current
        contents of the Info column (unless the current contents is empty, in which case no
        separator is added), followed by the specified string. 
    */
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "[Aeron Data]");

    ti = proto_tree_add_protocol_format(tree, proto_aerondata, tvb, 0, -1, "Aeron Data");
    data_tree = proto_item_add_subtree(ti, ett_aerondata);
    proto_tree_add_item(data_tree, hf_aerondata_magic, tvb, O_AERONDATA_MAGIC, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(data_tree, hf_aerondata_checksum, tvb, O_AERONDATA_CHECKSUM, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(data_tree, hf_aerondata_sqn, tvb, O_AERONDATA_SQN, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(data_tree, hf_aerondata_data, tvb, O_AERONDATA_DATA, tvb_reported_length_remaining(tvb, O_AERONDATA_DATA), ENC_NA);
    return (TRUE);
}

/* The registration hand-off routine */
void proto_reg_handoff_aerondata(void)
{
    /*
        This is where we tap into the Aeron dissector.

        Whenever an Aeron packet is dissected and finds a message payload,
        any registered heuristic subdissectors (HSDs) are called, in an order
        determined by Wireshark. If any HSD returns TRUE, it is assumed that that
        HSD has handled the packet, and no additional HSDs are invoked.

        So, this will essentially allow you to dissect your own Aeron application
        message contents.

        For your HSD to be called by the Aeron dissector, the Aeron "Use heuristic sub-dissectors"
        preference must be checked. As only full messages are passed to the HSD, the Aeron
        "Reassemble fragmented data" preference should also be checked. Otherwise, only unfragmented
        messages will be passed to the HSD.
    */
    heur_dissector_add("aeron_msg_payload", dissect_aerondata, proto_aerondata);
}

/* Register all the bits needed with the filtering engine */
void proto_register_aerondata(void)
{
    static hf_register_info hf[] =
    {
        { &hf_aerondata_magic,
            { "Magic", "aerondata.magic", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "", HFILL } },
        { &hf_aerondata_checksum,
            { "Checksum", "aerondata.checksum", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "", HFILL } },
        { &hf_aerondata_sqn,
            { "Sequence Number", "aerondata.sqn", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "", HFILL } },
        { &hf_aerondata_data,
            { "Data", "aerondata.data", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL } }
    };
    static gint * ett[] =
    {
        &ett_aerondata
    };

    /*
        If you need to allow customization of the dissector (via preferences),
        include a declaration such as:

        module_t * data_module;
    */

    proto_aerondata = proto_register_protocol("Aeron Data", "AeronData", "aerondata");
    
    proto_register_field_array(proto_aerondata, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*
        If you need to allow customization of the dissector (via preferences), this
        would be the place to register them:

        data_module = prefs_register_protocol(proto_aerondata, proto_reg_handoff_aerondata);
        prefs_register_uint_preference(aerondata_module, etc... );

        See the Wireshark documentation source for examples.
    */
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */