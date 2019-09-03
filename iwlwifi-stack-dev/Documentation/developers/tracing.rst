Auto-Generated Tracing System
=============================

Overview
--------

The original tracing system used hand-written code to list all the fields,
distinguish possible different versions of commands, etc. This was hard to
maintain.

The new system, instead, builds mostly on the code - with some glue logic
holding it together.

The following pieces are used from the code:

 * a subset of the kernel-doc documentation
 * C code for structures
 * C code for enums (values)


Workflow
--------

In order to add new commands to the tracing, the following steps need to be
taken:

#. Add the necessary structures to the appropriate ``fw/api/*.h`` header
   file.

#. Add the command ID to the ``fw/api/commands.h`` header file to the correct
   group enum, or for FMAC to ``enum iwl_fmac_cmds``.

#. Link from the command ID to the structure(s) as described below.

#. Link from the structure field kernel-doc to the enum etc. as appropriate,
   as described below.

#. Run ``create-parsing.py`` (in ``iwlwifi-tools``,
   ``trace-cmd/create-parsing.py`` with the working directory in the
   checkout of ``iwlwifi-stack-dev``. Store the output in the
   ``iwlwifi.json`` file already present in the tools repository, and commit
   the update there once the patch gets submitted in the driver.

#. Extra adjustments might be needed as described below, but should be rare.

Tracing Sources
---------------

As mentioned, the tracing structure layout data comes (mostly) from the
C code in the driver.

 * To get the command IDs, the scripting starts from ``enum
   iwl_mvm_command_groups`` from which kernel-doc links point to the command
   ID enums defining the correct IDs within the group.

   For FMAC, a special case adds the correct enum and group value for FMAC,
   this isn't done in the code.

 * At the top level, kernel-doc links from the command to structures are used
   to determine which structures are possible for a given command/notification
   ID; for example::

    /**
     * enum iwl_legacy_cmds - legacy group command IDs
     */
    enum iwl_legacy_cmds {
        /**
         * @MVM_ALIVE:
         * Alive data from the firmware, as described in
         * &struct mvm_alive_resp_v3 or &struct mvm_alive_resp.
         */
        MVM_ALIVE = 0x1,

   For the tracing system, the text is immaterial here, only the links are
   (currently) used.

   If multiple structures are mentioned, the default is to distuingish them
   by size. It's possible to override this, see below.

   .. note:: The whole enum must have a kernel-doc comment itself, even if
    inline comments are used; otherwise it doesn't show up in the
    documentation at all, and the tracing parser won't find the links.

 * The C code for each structure mentioned above is analysed. Not everything
   in C is currently understood by the parser, but most constructs can be
   used.

   The C struct and field names will later be shown in the tracing output.

 * Additional kernel-doc annotiations are used:

   array lengths
    Some firmware commands contain a variable length array (at the end)
    whose length is carried within the command itself, making the whole
    command variable length. In this case, it's possible to tell the
    tracing parser about this by adding to the kernel-doc comment of the
    array, anywhere in the comment, the text

    ::

      length in @field

    where ``field`` is the field containing the length of the array.

    .. note:: Currently, having the length in just a few bits of the
     command, via some enum, isn't supported.

    .. note:: Currently, implicit length (based on the size of the command
     itself) isn't supported.

    .. warning:: The code to determine which struct to show will currently
     not take the array sizes into account.

   enum values
    When kernel-doc links from a struct field to an enum, using ``&enum
    foo``, the tracing parser will pick up the values and attempt to show
    them in a sane way. The following heuristics are used:

    * enum values ending with ``POS`` or ``SHIFT`` are ignored, since
      they're assumed to be the bit position of something; we assume that
      there are also corresponding ``MASK`` (or ``MSK``) enum values.

    * enum values ending with ``MASK``, ``MSK`` or enum values that also
      have a corresponding ``_POS`` or ``_SHIFT`` entry (e.g. an enum that
      has both the entries ``FOO`` and ``FOO_SHIFT`` are assumed to be
      multi-bit values and shown as such::

       enum foo {
        FOO = 0xF00,
        FOO_SHIFT = 8,
       }

      will be shown as::

       FOO = 0x7 (0x700)


Tracing Overrides
-----------------

There's some logic in the ``iwlwifi_json.py`` code that allows overriding
the default behaviour:

 * Since all the kernel-doc/C code is parsed into a python representation of
   the data (which is serialized as JSON), the structure definitions can be
   overridden. This should be used very sparingly - preferring to put the
   correct thing into the code - but is used for the scan command size.

 * The ``_links`` variable normally contains strings that link to an enum,
   but it can be overridden with a function, for example we currently have::

    _links['iwl_lq_cmd:rs_table'] = _rate_n_flags

   This calls the function instead of parsing the bits from the enum data,
   which for the much-overloaded u32 value of rate_n_flags is the only way
   to parse it properly.

 * The ``_union_selectors`` array can override the default behaviour of
   showing all possible branches of a union, which can clutter the output
   too much. There's an example in the code::

    _union_selectors['iwl_mac_ctx_cmd:0'] = _select_mac_ctxt

 * The default behaviour of picking the C struct to use by size fails for
   certain variable-length structures, so this can be overridden using the
   ``_parser_selectors`` dictionary - some example are in the code.

   This can also be used to implement a separate parser class, which should
   be relatively rare but is used to show the 802.11 header in TX frames and
   could be used for RX to do the same.


Internal Details
----------------

The two-step process that reads the kernel-doc and C code separately,
creating the JSON serialization of the internal representation, is necessary
because the parsing/analysis is too slow to do when the data is needed, and
having to have the current driver just for tracing display would be a hassle.

Creating the parsing data
^^^^^^^^^^^^^^^^^^^^^^^^^

Most of the parsing logic is done by the ``create-parsing.py`` script, which
exports the discovered data serialized using JSON, which in turn is put into
``iwlwifi.json`` for further use.

This data is parsed from three sources:

The C code itself
 This is parsed using `pycparser <https://github.com/eliben/pycparser/>`_,
 which understands most of C but doesn't have a preprocessor built in, so
 the files are preprocessed with the regular CPP first.

 The following files are used:

  * mvm/fw-api*.h
  * fmac/fw-api-fmac.h
  * iwl-fw-file.h
  * iwl-fw-api.h
  * ieee80211.h

 .. note::
  Note that includes are stripped because not all of the Linux header file
  code parses well with pycparser. Therefore, only few types that are listed
  in the ``create-parsing.py`` script can be used in the code.

The kernel-doc contained in the code
 The second source of data is the kernel-doc in the code. This is parsed
 using the original kernel-doc script in "rst" output mode, that output is
 then further parsed by the script to find the links.

Some overrides within the script itself
 As described above, there are a few overrides, mostly for FMAC, in the
 script itself. This shouldn't be extended unless it can't be avoided.

Run-time code when displaying the trace
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The serialized representation of the C structures, enums and links between
them is loaded at runtime by the ``iwlwifi_json.py`` tracing code. This code
is loaded into the previous ``iwl_mvm.py``, which therefore retains the
ability to override everything done by the automatic tracing.

The runtime code determines the struct sizes, calls the overrides described
above, etc.
