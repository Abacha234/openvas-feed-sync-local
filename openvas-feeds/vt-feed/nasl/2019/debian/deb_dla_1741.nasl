# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891741");
  script_cve_id("CVE-2019-9022", "CVE-2019-9637", "CVE-2019-9638", "CVE-2019-9639", "CVE-2019-9640", "CVE-2019-9641");
  script_tag(name:"creation_date", value:"2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:49:00 +0000 (Tue, 05 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-1741)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1741");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1741");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DLA-1741 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in php5, a server-side, HTML-embedded scripting language.

CVE-2019-9637

rename() across the device may allow unwanted access during processing.

CVE-2019-9638

CVE-2019-9639

Uninitialized read in exif_process_IFD_in_MAKERNOTE.

CVE-2019-9640

Invalid Read on exif_process_SOFn.

CVE-2019-9641

Uninitialized read in exif_process_IFD_in_TIFF.

CVE-2019-9022

An issue during parsing of DNS responses allows a hostile DNS server to misuse memcpy, which leads to a read operation past an allocated buffer.

For Debian 8 Jessie, these problems have been fixed in version 5.6.40+dfsg-0+deb8u2.

We recommend that you upgrade your php5 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);