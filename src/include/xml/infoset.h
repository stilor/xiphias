/* vi: set ts=5 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

/** @file
    Handle for reading an XML entity.
*/

#ifndef __xml_infoset_h_
#define __xml_infoset_h_

/// XML version values
enum xml_info_version_e {
    XML_INFO_VERSION_NO_VALUE,     ///< Version not specified
    XML_INFO_VERSION_1_0,          ///< XML 1.0
    XML_INFO_VERSION_1_1           ///< XML 1.1
};

/// XML standalone status
enum xml_info_standalone_e {
    XML_INFO_STANDALONE_NO_VALUE,  ///< Standalone status not specified
    XML_INFO_STANDALONE_YES,       ///< Document is standalone
    XML_INFO_STANDALONE_NO,        ///< Document is not standalone
};


#endif
