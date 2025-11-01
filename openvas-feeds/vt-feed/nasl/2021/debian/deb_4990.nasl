# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704990");
  script_cve_id("CVE-2020-20445", "CVE-2020-20446", "CVE-2020-20453", "CVE-2020-21041", "CVE-2020-22015", "CVE-2020-22016", "CVE-2020-22017", "CVE-2020-22019", "CVE-2020-22020", "CVE-2020-22021", "CVE-2020-22022", "CVE-2020-22023", "CVE-2020-22025", "CVE-2020-22026", "CVE-2020-22027", "CVE-2020-22028", "CVE-2020-22029", "CVE-2020-22030", "CVE-2020-22031", "CVE-2020-22032", "CVE-2020-22033", "CVE-2020-22034", "CVE-2020-22035", "CVE-2020-22036", "CVE-2020-22037", "CVE-2020-22049", "CVE-2020-22054", "CVE-2020-35965", "CVE-2021-38114", "CVE-2021-38171", "CVE-2021-38291");
  script_tag(name:"creation_date", value:"2021-10-21 01:00:32 +0000 (Thu, 21 Oct 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-30 15:37:00 +0000 (Mon, 30 Aug 2021)");

  script_name("Debian: Security Advisory (DSA-4990)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4990");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4990");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ffmpeg");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ffmpeg' package(s) announced via the DSA-4990 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the FFmpeg multimedia framework, which could result in denial of service or potentially the execution of arbitrary code if malformed files/streams are processed.

For the oldstable distribution (buster), these problems have been fixed in version 7:4.1.8-0+deb10u1.

We recommend that you upgrade your ffmpeg packages.

For the detailed security status of ffmpeg please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);