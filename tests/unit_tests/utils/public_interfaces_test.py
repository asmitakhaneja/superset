# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from superset.utils.public_interfaces import compute_class_hash, compute_func_hash


def test_compute_func_hash_is_stable() -> None:
    """The digest must stay byte-identical to guard against hashing changes."""

    def some_function(a, b):  # pylint: disable=invalid-name
        return a + b

    assert compute_func_hash(some_function) == "j~`aRkCUUISehWVPV^*V"


def test_compute_class_hash_is_stable() -> None:
    """The digest must stay byte-identical to guard against hashing changes."""

    # pylint: disable=too-few-public-methods, invalid-name
    class SomeClass:
        def __init__(self, a, b):
            self.a = a
            self.b = b

        def add(self):
            return self.a + self.b

    assert compute_class_hash(SomeClass) == "X1Y{XqdQ_ycm1V+QoJro"
