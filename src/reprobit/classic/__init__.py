"""Classic i386 COFF, CodeView, and instruction-proof algorithms.

Algorithms live in focused modules such as :mod:`reprobit.classic.coff`,
:mod:`reprobit.classic.composition`, and :mod:`reprobit.classic.scheduling`.
Register work is split between :mod:`reprobit.classic.register_semantics`,
:mod:`reprobit.classic.register_bijection`,
:mod:`reprobit.classic.register_reencoding`, and
:mod:`reprobit.classic.register_candidates`. Import the module that owns the
operation instead of importing symbols from this package.
"""
