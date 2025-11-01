# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840520");
  script_cve_id("CVE-2010-3170", "CVE-2010-3173");
  script_tag(name:"creation_date", value:"2010-10-22 14:42:09 +0000 (Fri, 22 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1007-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1007-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1007-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr, nss' package(s) announced via the USN-1007-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Richard Moore discovered that NSS would sometimes incorrectly match an SSL
certificate which had a Common Name that used a wildcard followed by a partial
IP address. While it is very unlikely that a Certificate Authority would issue
such a certificate, if an attacker were able to perform a machine-in-the-middle
attack, this flaw could be exploited to view sensitive information.
(CVE-2010-3170)

Nelson Bolyard discovered a weakness in the Diffie-Hellman Ephemeral mode
(DHE) key exchange implementation which allowed servers to use a too small
key length. (CVE-2010-3173)");

  script_tag(name:"affected", value:"'nspr, nss' package(s) on Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
