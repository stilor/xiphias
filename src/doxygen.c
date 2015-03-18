/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */
/**
    @file
    This is not a real source file, but rather just text input for doxygen.

    @mainpage XML Processing Harness (XPH, Xiphias)
    Xiphias is a project by Alexey Neyman to implement in C the XML specifications
    for which the current implementations are lacking in some respect, incomplete
    or do not exist at all.

    @section SPECS Specifications being implemented
    - XML
      - Extensible Markup Language 1.0
      - Extensible Markup Language 1.1
      - Namespaces in XML 1.0
      - Namespaces in XML 1.1
      - XML Information Set
    - XPath
      - XPath 1.0
      - XPath 2.0
    - XSchema
      - XSchema 1.0
      - XSchema 1.1
    - XInclude
      - XInclude 1.0
      - XInclude 1.1
    - XSLT
      - XSLT 1.0
      - XSLT 2.0
    - XProc
      - XProc 1.0
      - XProc 2.0
    - XML Catalog

    @section OTHERFEATURES Other features under consideration
    - XML tree differ
    - Schema-aware XML indenter/formatter

    @section MILESTONES Next milestones
    - XML reader (event driver for DOM/SAX parsers)
    - DOM parser (XML Information Set)
    - SAX parser
    - Generic validator to be used by DTD/XML Schema/RelaxNG/...

    @section OPENISSUES Open issues
    @subsection OPENISSUES-XML XML 1.0/1.1
    - XML 1.1 normalization - scope of applicability (seems inconsistent as 'relevant 
      constructs' would apply to non-root element's attribute values, but not to root's
      attribute values, or to comments/PIs inside the root element, but not at the top
      level)
    - Reserved xml namespaces - latest errata in 1.0 changed the reservation from
      [Xx][Mm][Ll] to xml- in PIs and xml: in element and attribute names. There is
      no similar errata in XML 1.1 spec.
    - For the purposes of attribute value normalization, does "no declaration has been
      read" consider only declarations in DTD, or in other schema languages as well?
      For example, if attribute xxx is declared with type xs:ID in XML Schema, should
      an XML processor strip the leading/trailing spaces from its value in
      `<a xxx=" 123 "/>`? From the definition in 5.1, it looks like validating against
      XML Schema does not count as a "validation processor" - which seems kind of redundant
      given that constraints on logical structure of the documents can be expressed
      via XML Schema just as well.
    - Description of 'Not Recognized' rule for entities: "Similarly, the names of unparsed
      entities are not recognized except when they appear in the value of an appropriately
      declared attribute." - but the rules for unparsed entities are "Forbidden" rather
      than "Not Recognized". Unparsed entities are already mentioned under "Forbidden"
      rule, so no change is needed there.


    @page todo TODO list

    @section TODO-OTHER

    @todo genbuild.py: implement options/rules for installation of libraries/apps
*/
