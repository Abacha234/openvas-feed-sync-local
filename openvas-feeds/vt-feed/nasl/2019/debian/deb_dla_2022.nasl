# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892022");
  script_cve_id("CVE-2019-18609");
  script_tag(name:"creation_date", value:"2019-12-07 03:00:08 +0000 (Sat, 07 Dec 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-13 05:15:00 +0000 (Fri, 13 Mar 2020)");

  script_name("Debian: Security Advisory (DLA-2022)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2022");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-2022");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'librabbitmq' package(s) announced via the DLA-2022 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an integer overflow vulnerability in librabbitmq, a library for robust messaging between applications and servers.

CVE-2019-18609

An issue was discovered in amqp_handle_input in amqp_connection.c in rabbitmq-c 0.9.0. There is an integer overflow that leads to heap memory corruption in the handling of CONNECTION_STATE_HEADER. A rogue server could return a malicious frame header that leads to a smaller target_size value than needed. This condition is then carried on to a memcpy function that copies too much data into a heap buffer.

For Debian 8 Jessie, these problems have been fixed in version 0.5.2-2+deb8u1.

We recommend that you upgrade your librabbitmq packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'librabbitmq' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);