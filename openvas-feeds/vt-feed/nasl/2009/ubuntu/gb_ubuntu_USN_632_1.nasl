# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840343");
  script_cve_id("CVE-2008-1679", "CVE-2008-1721", "CVE-2008-1887", "CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-632-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-632-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-632-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.4, python2.5' package(s) announced via the USN-632-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were new integer overflows in the imageop
module. If an attacker were able to trick a Python application into
processing a specially crafted image, they could execute arbitrary code
with user privileges. (CVE-2008-1679)

Justin Ferguson discovered that the zlib module did not correctly
handle certain archives. If an attacker were able to trick a Python
application into processing a specially crafted archive file, they could
execute arbitrary code with user privileges. (CVE-2008-1721)

Justin Ferguson discovered that certain string manipulations in Python
could be made to overflow. If an attacker were able to pass a specially
crafted string through the PyString_FromStringAndSize function, they
could execute arbitrary code with user privileges. (CVE-2008-1887)

Multiple integer overflows were discovered in Python's core and modules
including hashlib, binascii, pickle, md5, stringobject, unicodeobject,
bufferobject, longobject, tupleobject, stropmodule, gcmodule, and
mmapmodule. If an attacker were able to exploit these flaws they could
execute arbitrary code with user privileges or cause Python applications
to crash, leading to a denial of service. (CVE-2008-2315, CVE-2008-2316,
CVE-2008-3142, CVE-2008-3143, CVE-2008-3144).");

  script_tag(name:"affected", value:"'python2.4, python2.5' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
