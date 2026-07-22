/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import { readFileSync } from 'fs';
import path from 'path';
import semver from 'semver';

const frontendRoot = path.resolve(__dirname, '..', '..');

const readJson = (relativePath: string) =>
  JSON.parse(readFileSync(path.resolve(frontendRoot, relativePath), 'utf8'));

const packageJson = readJson('package.json');
const packageLock = readJson('package-lock.json');

const jqueryRange: string = packageJson.dependencies.jquery;
const typesRange: string = packageJson.devDependencies['@types/jquery'];

const lockedVersion = (name: string): string => {
  const entry = packageLock.packages?.[`node_modules/${name}`];
  if (!entry?.version) {
    throw new Error(`No locked version found for ${name} in package-lock.json`);
  }
  return entry.version;
};

// Regression guard for GH issue #1: jquery was pinned to "^4.0.0", a range with
// no stable GA release at the time. A caret range against a version that only
// exists as prerelease tags produces non-reproducible installs. These
// assertions fail if the manifest range or the locked version ever drifts back
// to a prerelease-only pin.
test('jquery is pinned to a range with a real stable release', () => {
  expect(semver.validRange(jqueryRange)).not.toBeNull();

  // The floor of the declared range must be a stable (non-prerelease) version.
  const floor = semver.minVersion(jqueryRange);
  expect(floor).not.toBeNull();
  expect(semver.prerelease(floor!)).toBeNull();

  // The version npm actually locked must be stable and satisfy the range.
  const locked = lockedVersion('jquery');
  expect(semver.prerelease(locked)).toBeNull();
  expect(semver.satisfies(locked, jqueryRange)).toBe(true);
});

test('@types/jquery major matches the jquery major', () => {
  const jqueryMajor = semver.major(semver.minVersion(jqueryRange)!);
  const typesMajor = semver.major(semver.minVersion(typesRange)!);
  expect(typesMajor).toBe(jqueryMajor);

  const lockedTypes = lockedVersion('@types/jquery');
  expect(semver.major(lockedTypes)).toBe(jqueryMajor);
  expect(semver.satisfies(lockedTypes, typesRange)).toBe(true);
});
