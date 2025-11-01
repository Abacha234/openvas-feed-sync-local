# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53191");
  script_cve_id("CVE-2004-0399", "CVE-2004-0400");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-501)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-501");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-501");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exim' package(s) announced via the DSA-501 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Georgi Guninski discovered two stack-based buffer overflows. They can not be exploited with the default configuration from the Debian system, though. The Common Vulnerabilities and Exposures project identifies the following problems that are fixed with this update:

CAN-2004-0399

When 'sender_verify = true' is configured in exim.conf a buffer overflow can happen during verification of the sender. This problem is fixed in exim 4.

CAN-2004-0400

When headers_check_syntax is configured in exim.conf a buffer overflow can happen during the header check. This problem does also exist in exim 4.

For the stable distribution (woody) these problems have been fixed in version 3.35-1woody3.

For the unstable distribution (sid) these problems have been fixed in version 3.36-11 for exim 3 and in version 4.33-1 for exim 4.

We recommend that you upgrade your exim package.");

  script_tag(name:"affected", value:"'exim' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);