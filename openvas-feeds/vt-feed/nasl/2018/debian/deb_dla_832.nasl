# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890832");
  script_cve_id("CVE-2016-10188", "CVE-2016-10189");
  script_tag(name:"creation_date", value:"2018-03-28 22:00:00 +0000 (Wed, 28 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Debian: Security Advisory (DLA-832)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-832");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-832");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bitlbee' package(s) announced via the DLA-832 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-5668

Fix for incomplete fix for Null pointer dereference with file transfer request from unknown contacts. (Though this package wasn't in Wheezy with this issue, I mention it here. The fix was done with the second patch for CVE-2016-10189)

CVE-2016-10189

Null pointer dereference with file transfer request from unknown contacts.

CVE-2016-10188

deactivate any incoming file transfer for bitlbee This affects any libpurple protocol when used through BitlBee. It does not affect other libpurple-based clients such as pidgin.

For Debian 7 Wheezy, these issues have been fixed in bitlbee version 3.0.5-1.2+deb7u1");

  script_tag(name:"affected", value:"'bitlbee' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);