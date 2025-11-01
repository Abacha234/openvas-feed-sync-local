# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893326");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2023-02-21 02:00:22 +0000 (Tue, 21 Feb 2023)");
  script_name("Debian LTS: Security Advisory for isc-dhcp (DLA-3326-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/02/msg00020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3326-1");
  script_xref(name:"Advisory-ID", value:"DLA-3326-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1022969");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'isc-dhcp'
  package(s) announced via the DLA-3326-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Under not completely understood conditions, dhclient completely removes
IPv6 addresses from use and is unable to restore them.");

  script_tag(name:"affected", value:"'isc-dhcp' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
4.4.1-2+deb10u3.

We recommend that you upgrade your isc-dhcp packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
