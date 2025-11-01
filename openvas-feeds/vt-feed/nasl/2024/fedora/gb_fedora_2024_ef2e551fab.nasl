# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886502");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-25713");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-05-27 10:42:16 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for yyjson (FEDORA-2024-ef2e551fab)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ef2e551fab");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6KQ67T4R7QEWURW5NMCCVLTBASL4ECHE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yyjson'
  package(s) announced via the FEDORA-2024-ef2e551fab advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A high performance JSON library written in ANSI C.

Features

  - Fast: can read or write gigabytes per second JSON data on modern CPUs.

  - Portable: complies with ANSI C (C89) for cross-platform compatibility.

  - Strict: complies with RFC 8259 JSON standard, ensuring strict number format
and UTF-8 validation.

  - Extendable: offers options to allow comments, trailing commas, NaN/Inf, and
custom memory allocator.

  - Accuracy: can accurately read and write int64, uint64, and double numbers.

  - Flexible: supports unlimited JSON nesting levels, \u0000 characters, and non
null-terminated strings.

  - Manipulation: supports querying and modifying using JSON Pointer, JSON Patch
and JSON Merge Patch.

  - Developer-Friendly: easy integration with only one h and one c file.");

  script_tag(name:"affected", value:"'yyjson' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
