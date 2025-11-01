# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54373");
  script_cve_id("CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-757)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-757");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-757");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-757 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Wachdorf reported two problems in the MIT krb5 distribution used for network authentication. First, the KDC program from the krb5-kdc package can corrupt the heap by trying to free memory which has already been freed on receipt of a certain TCP connection. This vulnerability can cause the KDC to crash, leading to a denial of service. [CAN-2005-1174] Second, under certain rare circumstances this type of request can lead to a buffer overflow and remote code execution. [CAN-2005-1175]

Additionally, Magnus Hagander reported another problem in which the krb5_recvauth function can in certain circumstances free previously freed memory, potentially leading to the execution of remote code. [CAN-2005-1689]

All of these vulnerabilities are believed difficult to exploit, and no exploits have yet been discovered.

For the old stable distribution (woody), these problems have been fixed in version 1.2.4-5woody10. Note that woody's KDC does not have TCP support and is not vulnerable to CAN-2005-1174.

For the stable distribution (sarge), these problems have been fixed in version 1.3.6-2sarge2.

For the unstable distribution (sid), these problems have been fixed in version 1.3.6-4.

We recommend that you upgrade your krb5 package.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);