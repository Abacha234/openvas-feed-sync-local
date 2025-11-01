# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886750");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-32039", "CVE-2024-32040", "CVE-2024-32041", "CVE-2024-32458", "CVE-2024-32459", "CVE-2024-32460", "CVE-2024-32658", "CVE-2024-32659", "CVE-2024-32660", "CVE-2024-32661", "CVE-2024-32662");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-05-27 10:46:20 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for freerdp2 (FEDORA-2024-982a7184e0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-982a7184e0");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5JL476WVJSIE7SBUKVJRVA6A52V2HOLZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp2'
  package(s) announced via the FEDORA-2024-982a7184e0 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The xfreerdp & wlfreerdp Remote Desktop Protocol (RDP) clients from the FreeRDP
project.

xfreerdp & wlfreerdp can connect to RDP servers such as Microsoft Windows
machines, xrdp and VirtualBox.");

  script_tag(name:"affected", value:"'freerdp2' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
