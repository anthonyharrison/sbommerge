# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import pathlib
import sys
import textwrap
from collections import ChainMap
from pathlib import Path

from lib4sbom.data.file import SBOMFile
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.generator import SBOMGenerator
from lib4sbom.parser import SBOMParser
from lib4sbom.sbom import SBOM

from sbommerge.version import VERSION

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "sbommerge"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            SBOMMerge merges two Software Bill of Materials (SBOMs)
            documents together.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "--sbom",
        action="store",
        default="auto",
        choices=["auto", "spdx", "cyclonedx"],
        help="specify type of sbom to merge (default: auto)",
    )
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="show debug information",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="tag",
        choices=["tag", "json", "yaml"],
        help="specify format of generated sbom (default: tag)",
    )
    output_group.add_argument(
        "--sbom-type",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to merge (default: spdx)",
    )
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )
    parser.add_argument("-V", "--version", action="version", version=VERSION)

    parser.add_argument("FILE1", help="first SBOM file")
    parser.add_argument("FILE2", help="second SBOM file")

    defaults = {
        "output_file": "",
        "sbom": "auto",
        "format": "tag",
        "sbom_type": "spdx",
        "debug": False,
    }
    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters
    if args["FILE1"] != args["FILE2"]:
        # Check both files exist
        file_found = True
        if not pathlib.Path(args["FILE1"]).exists():
            print(f"{args['FILE1']} does not exist")
            file_found = False
        if not pathlib.Path(args["FILE2"]).exists():
            print(f"{args['FILE2']} does not exist")
            file_found = False
        if not file_found:
            return -1
    else:
        # Same filename specified
        print("Must specify different filenames.")
        return -1

    parser = SBOMParser(args["sbom"])
    parser.parse_file(args["FILE1"])
    files1 = parser.get_files()
    packages1 = parser.get_packages()
    relationship1 = parser.get_relationships()
    file1_type = parser.get_type()

    # Reset type for parsing second SBOM
    parser.set_type(args["sbom"])
    parser.parse_file(args["FILE2"])
    files2 = parser.get_files()
    packages2 = parser.get_packages()
    relationship2 = parser.get_relationships()
    file2_type = parser.get_type()
    if args["debug"]:
        print(f'File {args["FILE1"]} - {file1_type}')
        print(f"Files: {files1}")
        print(f"Packages: {packages1}")
        print(f"Relationships {relationship1}")
        print(f'File {args["FILE2"]} - {file2_type}')
        print(f"Files: {files2}")
        print(f"Packages: {packages2}")
        print(f"Relationships {relationship2}")

    bom_format = args["sbom_type"]
    # bom_format = "cyclonedx" if file1_type == file2_type == "cyclonedx" else "spdx"
    # Ensure format is aligned with type of SBOM
    sbom_format = args["format"]
    if bom_format == "cyclonedx":
        sbom_format = "json"

    # Keep count of differences
    updated_info = 0
    identical_info = 0
    additional_info = 0
    merged_info = 0

    # Process files
    sbom_file = SBOMFile()
    files = {}
    for file in files1:
        sbom_file.initialise()
        if file in files2:
            for file2 in files2:
                if file2["name"] == file["name"]:
                    # Process each parameter
                    for param in file:
                        p1 = file[param]
                        if param in file2:
                            p2 = file2[param]
                            if p1 == p2:
                                sbom_file.set_value(param, p1)
                                identical_info += 1
                            else:
                                # Difference detected.
                                # If value is NOASSERTION, take other value
                                value = p1
                                if p1 == "NOASSERTION":
                                    value = p2
                                if args["debug"]:
                                    print(param, p1, p2, "CHANGED TO", value)
                                sbom_file.set_value(param, value)
                                updated_info += 1
                        else:
                            sbom_file.set_value(param, p1)
                            additional_info += 1
                    for param in file2:
                        if param not in file:
                            if args["debug"]:
                                print(param, "----", file2[param], "NEW")
                            sbom_file.set_value(param, file2[param])
        else:
            if args["debug"]:
                print(file["name"], "UNIQUE 1")
            sbom_file.copy_file(file)
            merged_info += 1
        files[sbom_file.get_name()] = sbom_file.get_file()
    for file in files2:
        sbom_file.initialise()
        if len(files1) > 0:
            if file not in files1:
                if args["debug"]:
                    print(file["name"], "UNIQUE 2")
                sbom_file.copy_file(file)
                merged_info += 1
                files[sbom_file.get_name()] = sbom_file.get_file()
        else:
            sbom_file.copy_file(file)
            identical_info += 1
            files[sbom_file.get_name()] = sbom_file.get_file()

    sbom_package = SBOMPackage()
    sbom_relationship = SBOMRelationship()
    packages = {}
    relationships = []

    # Create root package
    sbom_package.initialise()
    root_package = f'MERGETOOL-{Path(args["FILE1"]).name.replace(".","-")}-{Path(args["FILE2"]).name.replace(".","-")}'
    parent = f"SBOM-{root_package}"
    sbom_package.set_name(root_package)
    sbom_package.set_type("application")
    sbom_package.set_filesanalysis(False)
    # sbom_package.set_downloadlocation(sbom_root)
    license = "NOASSERTION"
    sbom_package.set_licensedeclared(license)
    sbom_package.set_licenseconcluded(license)
    sbom_package.set_supplier("UNKNOWN", "NOASSERTION")
    # Store package data
    packages[
        (sbom_package.get_name(), sbom_package.get_value("version"))
    ] = sbom_package.get_package()
    sbom_relationship.initialise()
    sbom_relationship.set_relationship(parent, "DESCRIBES", root_package)
    relationships.append(sbom_relationship.get_relationship())
    for package in packages1:
        sbom_package.initialise()
        if package in packages2:
            # If package version differ, don't merge
            for package2 in packages2:
                if package2["name"] == package["name"]:
                    if "version" in package.keys() and "version" in package2.keys() and package["version"] != package2["version"]:
                        print(
                            f"[ERROR] Version mismatch for"
                            f" {package['name']}"
                            f" - {package['version']}"
                            f" {package2['version']}"
                        )
                        continue
                    else:
                        # Process each parameter within package
                        for param in package:
                            p1 = package[param]
                            if param in package2:
                                p2 = package2[param]
                                if p1 == p2:
                                    sbom_package.set_value(param, p1)
                                    identical_info += 1
                                else:
                                    # Difference detected.
                                    # If value is NOASSERTION, take other value
                                    value = p1
                                    if p1 == "NOASSERTION":
                                        value = p2
                                    if args["debug"]:
                                        print(param, p1, p2, "CHANGED TO", value)
                                    sbom_package.set_value(param, value)
                                    updated_info += 1
                            else:
                                sbom_package.set_value(param, p1)
                                additional_info += 1
                        for param in package2:
                            if param not in package:
                                if args["debug"]:
                                    print(f"{param} ---- {package2[param]} NEW")
                                sbom_package.set_value(param, package2[param])
        else:
            if args["debug"]:
                print(package["name"], "UNIQUE 12")
            sbom_package.copy_package(package)
            merged_info += 1
        packages[
            (sbom_package.get_name(), sbom_package.get_value("version"))
        ] = sbom_package.get_package()
    for package in packages2:
        sbom_package.initialise()
        if package not in packages1:
            if args["debug"]:
                print(package["name"], "UNIQUE 2")
            sbom_package.copy_package(package)
            merged_info += 1
            packages[
                (sbom_package.get_name(), sbom_package.get_value("version"))
            ] = sbom_package.get_package()
    # Now process relationships
    for r in relationship1:
        source = None
        target = None
        source_type = "package"
        target_type = "package"
        # Could be file or package
        for f in files1:
            if f["name"] == r["source"]:
                source = f["name"]
                source_type = "file"
            elif f["name"] == r["target"]:
                target = f["name"]
                target_type = "file"
        for p in packages1:
            if p["name"] == r["source"]:
                source = p["name"]
            elif p["name"] == r["target"]:
                target = p["name"]
        if source is not None and target is not None:
            sbom_relationship.initialise()
            sbom_relationship.set_relationship(source, r["type"], target)
            sbom_relationship.set_source_type(source_type)
            sbom_relationship.set_target_type(target_type)
            relationships.append(sbom_relationship.get_relationship())

    for r in relationship2:
        source = None
        target = None
        source_type = "package"
        target_type = "package"
        # Could be file or package
        for f in files2:
            if f["name"] == r["source"]:
                source = f["name"]
                source_type = "file"
            elif f["name"] == r["target"]:
                target = f["name"]
                target_type = "file"
        for p in packages2:
            if p["name"] == r["source"]:
                source = p["name"]
            elif p["name"] == r["target"]:
                target = p["name"]
        if source is not None and target is not None:
            sbom_relationship.initialise()
            sbom_relationship.set_relationship(source, r["type"], target)
            sbom_relationship.set_source_type(source_type)
            sbom_relationship.set_target_type(target_type)
            relationships.append(sbom_relationship.get_relationship())

    # Finally add relationships to overall document
    for p in packages:
        sbom_relationship.initialise()
        sbom_relationship.set_relationship(root_package, "CONTAINS", p[0])
        relationships.append(sbom_relationship.get_relationship())
    if args["debug"]:
        print("SBOM type", bom_format)
        print("SBOM format", sbom_format)
        print("Output file", args["output_file"])
        print("SBOM File1", args["FILE1"])
        print("SBOM File1 - type", file1_type)
        print("SBOM File1 - files", len(files1))
        print("SBOM File1 - packages", len(packages1))
        print("SBOM File1 - relationships", len(relationship1))
        print("SBOM File2", args["FILE2"])
        print("SBOM File2 - type", file2_type)
        print("SBOM File2 - files", len(files2))
        print("SBOM File2 - packages", len(packages2))
        print("SBOM File2 - relationships", len(relationship2))

    print("\nSummary\n-------", file=sys.stderr)
    print(f"No change:  {identical_info}", file=sys.stderr)
    print(f"Updated:    {updated_info}", file=sys.stderr)
    print(f"New:        {additional_info}", file=sys.stderr)
    print(f"Merged:     {merged_info}\n", file=sys.stderr)

    # Generate SBOM file

    merge_sbom = SBOM()
    merge_sbom.add_files(files)
    merge_sbom.add_packages(packages)
    merge_sbom.add_relationships(relationships)
    if args["debug"]:
        print(merge_sbom.get_sbom())

    sbom_gen = SBOMGenerator(
        sbom_type=bom_format, format=sbom_format, application=app_name, version=VERSION
    )
    sbom_gen.generate(
        project_name=parent,
        sbom_data=merge_sbom.get_sbom(),
        filename=args["output_file"],
    )

    # Return code indicates if any differences have been detected
    if (updated_info or additional_info or merged_info) != 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
