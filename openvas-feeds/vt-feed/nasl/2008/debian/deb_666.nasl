# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53496");
  script_cve_id("CVE-2005-0089");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-666)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-666");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-666");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python2.2' package(s) announced via the DSA-666 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Python development team has discovered a flaw in their language package. The SimpleXMLRPCServer library module could permit remote attackers unintended access to internals of the registered object or its module or possibly other modules. The flaw only affects Python XML-RPC servers that use the register_instance() method to register an object without a _dispatch() method. Servers using only register_function() are not affected.

For the stable distribution (woody) this problem has been fixed in version 2.2.1-4.7. No other version of Python in woody is affected.

For the testing (sarge) and unstable (sid) distributions the following matrix explains which version will contain the correction in which version:



testing

unstable

Python 2.2

2.2.3-14

2.2.3-14

Python 2.3

2.3.4-20

2.3.4+2.3.5c1-2

Python 2.4

2.4-5

2.4-5

We recommend that you upgrade your Python packages.");

  script_tag(name:"affected", value:"'python2.2' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);