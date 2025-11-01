# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856445");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2016-4332", "CVE-2017-17507", "CVE-2018-11202", "CVE-2018-11205", "CVE-2019-8396", "CVE-2020-10812", "CVE-2021-37501", "CVE-2024-29158", "CVE-2024-29161", "CVE-2024-29166", "CVE-2024-32608", "CVE-2024-32610", "CVE-2024-32614", "CVE-2024-32619", "CVE-2024-32620", "CVE-2024-33873", "CVE-2024-33874", "CVE-2024-33875");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-17 16:47:02 +0000 (Thu, 17 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-09-07 04:00:39 +0000 (Sat, 07 Sep 2024)");
  script_name("openSUSE: Security Advisory for hdf5, netcdf, trilinos (SUSE-SU-2024:3144-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3144-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7OFTEFNAJPV4UBTWDWNQRFMOYIVUMAX5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hdf5, netcdf, trilinos'
  package(s) announced via the SUSE-SU-2024:3144-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hdf5, netcdf, trilinos fixes the following issues:

  hdf5 was updated from version 1.10.8 to 1.10.11:

  * Security issues fixed:

  * CVE-2019-8396: Fixed problems with malformed HDF5 files where content does
      not match expected size. (bsc#1125882)

  * CVE-2018-11202: Fixed that a malformed file could result in chunk index
      memory leaks. (bsc#1093641)

  * CVE-2016-4332: Fixed an assertion in a previous fix for this issue
      (bsc#1011205).

  * CVE-2020-10812: Fixed a segfault on file close in h5debug which fails with a
      core dump on a file that has an illegal file size in its cache image.Fixes
      HDFFV-11052, (bsc#1167400).

  * CVE-2021-37501: Fixed buffer overflow in hdf5-h5dump (bsc#1207973)

  * Other security issues fixed (bsc#1224158):

  * CVE-2024-29158, CVE-2024-29161, CVE-2024-29166, CVE-2024-32608,

  * CVE-2024-32610, CVE-2024-32614, CVE-2024-32619, CVE-2024-32620,

  * CVE-2024-33873, CVE-2024-33874, CVE-2024-33875

  * Additionally, these fixes resolve crashes triggered by the reproducers for CVE-2017-17507, CVE-2018-11205. These crashes appear to be unrelated to the original problems

  * Other issues fixed:

  * Remove timestamp/buildhost/kernel version from libhdf5.settings
      (bsc#1209548)

  * Changed the error handling for a not found path in the find plugin process.

  * Fixed a file space allocation bug in the parallel library for chunked
      datasets.

  * Fixed an assertion failure in Parallel HDF5 when a file can't be created due
      to an invalid library version bounds setting.

  * Fixed memory leaks that could occur when reading a dataset from a malformed
      file.

  * Fixed a bug in H5Ocopy that could generate invalid HDF5 files

  * Fixed potential heap buffer overflow in decoding of link info message.

  * Fixed potential buffer overrun issues in some object header decode routines.

  * Fixed a heap buffer overflow that occurs when reading from a dataset with a
      compact layout within a malformed HDF5 file.

  * Fixed memory leak when running h5dump with proof of vulnerability file.

  * Added option --no-compact-subset to h5diff

  * Several improvements to parallel compression feature, including:

  * Improved support for collective I/O (for both writes and reads).

  * Reduction of copying of application data buffers passed to H5Dwrite.

  * Addition of support for incremental file space allocation for filtered datasets created in parallel.

  * Addition of support for HDF5's 'don't filter partial edge chunks' flag

  * Additio ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'hdf5, netcdf, trilinos' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
