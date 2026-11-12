import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location(
    "rp", Path(__file__).parent / ".." / "tools" / "resolve_patterns.py")
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)


class Img:
    """Sparse image stub: put() then rva2off()/buf behave like Ctx.img."""

    def __init__(self):
        self.buf = bytearray(b"\x00")
        self.off = {}

    def put(self, rva, data):
        self.off[rva] = len(self.buf)
        self.buf += bytes(data)

    def rva2off(self, rva):
        return self.off.get(rva)


def mkctx(entries=(), callees=None, callers=None, refs=None,
          rstrings=None, sizes=None, img=None, **extra):
    ns = SimpleNamespace(
        entries=list(entries),
        img=img or Img(),
        callees=lambda f: set((callees or {}).get(f, ())),
        callers_map=lambda: dict(callers or {}),
        referencing_funcs=lambda s: set((refs or {}).get(s, ())),
        refs_by_func=lambda: dict(rstrings or {}),
        func_size=lambda f: (sizes or {}).get(f, 0x100),
        vtable_runs=lambda: extra.get("runs", []),
        e8_count_many=lambda pts: {p: extra.get("e8", {}).get(p, 0)
                                   for p in pts},
        iat_slots=lambda *a: extra.get("slots", []),
        ff15_refs=lambda slots: extra.get("ff15", {}),
        prefix_index=lambda n: extra.get("prefix", {}),
        func_of=lambda f: f,
    )
    return ns


class TestHelpers(unittest.TestCase):
    def test_only(self):
        self.assertEqual(rp._only([7], "x"), (7, None))
        v, e = rp._only([], "x")
        self.assertIsNone(v)
        self.assertIn("0 x", e)
        v, e = rp._only([1, 2], "x")
        self.assertIsNone(v)
        self.assertIn("2 x", e)

    def test_min_unique(self):
        self.assertEqual(rp._min_unique([(1, 5), (2, 9)], "x"), (1, None))
        v, e = rp._min_unique([(1, 5), (2, 5)], "x")
        self.assertIsNone(v)
        self.assertIn("tie x", e)
        v, e = rp._min_unique([], "x")
        self.assertIsNone(v)
        self.assertIn("0 x", e)

    def test_max_unique(self):
        self.assertEqual(rp._max_unique([(1, 5), (2, 9)], "x"), (2, None))
        v, e = rp._max_unique([(1, 5), (2, 5)], "x")
        self.assertIsNone(v)
        self.assertIn("tie x", e)


class TestFnvPins(unittest.TestCase):
    """FNV section ids are load-bearing: pin the known vectors."""

    def test_vectors(self):
        self.assertEqual(rp.fnv1a("BuildDepotDependency"), 0xC37F2D8E)
        self.assertEqual(rp.fnv1a("RecvPkt"), 0x836FF9F0)
        self.assertEqual(rp.fnv1a("ProcessPendingLicenseUpdates"), 0x103B52AA)
        self.assertEqual(rp.fnv1a("GetAppIDForCurrentPipe"), 0xA185DB47)
        self.assertEqual(rp.fnv1a("PchMsgNameFromEMsg"), 0x0F926D0A)
        self.assertEqual(rp.fnv1a("CUtlMemoryGrow"), 0x2D945919)


class TestBBuild(unittest.TestCase):
    BB, BODY = 0xD311D0, 0xD311DF
    ENTRIES = [0x1000, BB, BODY, 0xD31AF2, 0xD31B45, 0xD32702, 0xD32740]
    SIZES = {BB: 0xF, 0xD31AF2: 0x53, 0xD32702: 0x3E}

    def test_tiny_prev(self):
        ctx = mkctx(entries=self.ENTRIES, sizes=self.SIZES,
                    refs={rp.WS_NAME: {self.BODY, 0xD31B45, 0xD32740}})
        self.assertEqual(rp.p2_bbuild(ctx), (self.BB, None))

    def test_wrong_refcount_fails(self):
        ctx = mkctx(refs={rp.WS_NAME: {self.BODY, 0xD31B45}})
        v, e = rp.p2_bbuild(ctx)
        self.assertIsNone(v)
        self.assertIn("2 NAME referrers", e)


class TestGrow(unittest.TestCase):
    GROW, DECOY = 0xE8400, 0xAAAA
    HUB = 0x4B0A17

    def _ctx(self, hub_callees):
        img = Img()
        img.put(self.GROW, rp.GROW_PREFIX + b"\xee\x00\x00\x00\x2b\xca")
        img.put(self.DECOY, rp.GROW_PREFIX + b"\xed\x00\x00\x00\x2b\xca")
        return mkctx(entries=[self.GROW, self.DECOY, 0xCCCC], img=img,
                     callees={self.HUB: set(hub_callees)})

    def test_hub_callee_wins_over_twins(self):
        ctx = self._ctx([self.GROW, 0xCCCC])
        self.assertEqual(rp.p2_grow(ctx, self.HUB), (self.GROW, None))

    def test_no_hub_prefix_match_fails(self):
        ctx = self._ctx([0xCCCC])
        v, e = rp.p2_grow(ctx, self.HUB)
        self.assertIsNone(v)
        self.assertIn("0 Grow cands", e)


class TestBuildDepot(unittest.TestCase):
    HOOK, STRFUNC = 0x4C3820, 0x4C383E

    def test_prev_entry_is_hook(self):
        ctx = mkctx(entries=[self.HOOK, self.STRFUNC],
                    refs={rp.BD_STR: {self.STRFUNC}})
        self.assertEqual(rp.p2_builddepot(ctx), (self.HOOK, None))

    def test_no_ref_fails(self):
        ctx = mkctx(refs={rp.BD_STR: set()})
        v, e = rp.p2_builddepot(ctx)
        self.assertIsNone(v)
        self.assertIn("0 BuildDepot referrers", e)

    def test_checkapp_min_callers(self):
        ctx = mkctx(callees={self.STRFUNC: {0x4B3EE0, 0x9CE9E0}},
                    callers={0x4B3EE0: range(173), 0x9CE9E0: range(27)},
                    refs={rp.BD_STR: {self.STRFUNC}})
        self.assertEqual(rp.p2_checkapp(ctx, ctx.callers_map()),
                         (0x9CE9E0, None))


class TestHub(unittest.TestCase):
    def test_pair_rule(self):
        ctx = mkctx(rstrings={0x4B0A17: list(rp.HUB_REFS),
                              0x9: [rp.HUB_REFS[0]]})
        self.assertEqual(rp.p2_hub(ctx), (0x4B0A17, None))


class TestConfigStore(unittest.TestCase):
    F1, F2, C, A = 0xF1, 0xF2, 0xC, 0xA

    def _ctx(self, c1, c2):
        return mkctx(
            callees={self.F1: {self.C} | c1, self.F2: {self.C} | c2},
            rstrings={self.C: ["RGBA: x"], self.A: []},
            refs={"unhandled EConfigStore (%u)": {self.F1, self.F2}})

    def test_superset_wins(self):
        self.assertEqual(rp.p2_configstore(self._ctx({self.A}, set())),
                         (self.F1, None))

    def test_no_superset_fails(self):
        v, e = rp.p2_configstore(self._ctx(set(), set()))
        self.assertIsNone(v)
        self.assertIn("no superset", e)


class TestClientChain(unittest.TestCase):
    def test_loadpackage_max_callees(self):
        ctx = mkctx(callees={0x1: {0xA, 0xB}, 0xA: {1, 2, 3}, 0xB: {1}})
        self.assertEqual(rp.p2_loadpackage(ctx, 0x1), (0xA, None))

    def test_marklicense(self):
        ctx = mkctx(callees={0x1: {0xA, 0xB, 0xC}, 0xC: {9}},
                    callers={0xA: range(5), 0xB: range(50)})
        self.assertEqual(rp.p2_marklicense(ctx, 0x1, ctx.callers_map()),
                         (0xA, None))

    def test_readasbin(self):
        ctx = mkctx(callees={0x1: {0xA, 0xB}},
                    callers={0xA: range(13), 0xB: range(53)})
        self.assertEqual(rp.p2_readasbin(ctx, 0x1, ctx.callers_map()),
                         (0xA, None))

    def test_findcreate_window_max(self):
        rb = 0xD17160
        ctx = mkctx(entries=[0xD13470, 0xD143D0, 0xD14B90, 0x300000],
                    callers={0xD13470: range(118), 0xD143D0: range(216),
                             0xD14B90: range(110)})
        self.assertEqual(rp.p2_findcreate(ctx, rb, ctx.callers_map()),
                         (0xD143D0, None))

    def test_findcreate_window_preferred(self):
        # 原窗口内有候选就不回退，即使前一页的调用次数更高
        rb = 0xD17160
        ctx = mkctx(entries=[0xD07100, 0xD13470],
                    callers={0xD07100: range(400), 0xD13470: range(120)})
        self.assertEqual(rp.p2_findcreate(ctx, rb, ctx.callers_map()),
                         (0xD13470, None))

    def test_findcreate_cross_page_fallback(self):
        # ReadAsBinary 跨过 64KB 边界后，FindOrCreateKey 仍留在前一页
        rb = 0xDA0AE0
        ctx = mkctx(entries=[0xD9DEC0, 0xDA3690],
                    callers={0xD9DEC0: range(170), 0xDA3690: range(51)})
        self.assertEqual(rp.p2_findcreate(ctx, rb, ctx.callers_map()),
                         (0xD9DEC0, None))

    def test_findcreate_cross_page_max(self):
        # 回退页内多个候选取调用次数最大者
        rb = 0xDA0AE0
        ctx = mkctx(entries=[0xD9CFA0, 0xD9DEC0, 0xD9E680],
                    callers={0xD9CFA0: range(112), 0xD9DEC0: range(170),
                             0xD9E680: range(104)})
        self.assertEqual(rp.p2_findcreate(ctx, rb, ctx.callers_map()),
                         (0xD9DEC0, None))

    def test_pplu(self):
        P1, P1E, P2, P2E, U = 0x5001, 0x5002, 0x5003, 0x5004, 0x6001
        img = Img()
        img.put(P1, b"\x41\x56" + b"\x00" * 20
                + b"\x83\xb9\x98\x24\x00\x00\x00")
        img.put(P1E, b"\x00" * 8)
        img.put(P2, b"\x90" * 32)
        img.put(P2E, b"\x00" * 8)
        ctx = mkctx(entries=[P1, P1E, P2, P2E], img=img,
                    refs={rp.UR_STR: {U}},
                    callees={U: {P1, P2}},
                    sizes={P1: 0x14, P2: 0x500})
        self.assertEqual(rp.p2_pplu(ctx), (P1, None))

    def test_recvpkt(self):
        ms = [0x7000 + i * 0x10 for i in range(5)]
        ctx = mkctx(rstrings={ms[2]: [rp.CC_STR]},
                    sizes={ms[0]: 0x18},
                    runs=[(0x8000, ms)])
        self.assertEqual(rp.p2_recvpkt(ctx), (ms[0], None))

    def test_appid(self):
        a, b = 0x9001, 0x9002
        ctx = mkctx(entries=[a, b], sizes={a: 0x174, b: 0x174},
                    e8={a + 0xA4: 341, b + 0xA4: 3})
        self.assertEqual(rp.p2_appid(ctx), (a + 0xA4, None))

    def test_pipeclient(self):
        a, b = 0xA001, 0xA002
        ctx = mkctx(entries=[a, b], sizes={a: 0x150, b: 0x150},
                    e8={a + 0xA0: 15, b + 0xA0: 0})
        self.assertEqual(rp.p2_pipeclient(ctx), (a + 0xA0, None))

    def test_getoradd(self):
        ctx = mkctx(callees={0x1: {0xA, 0xB}}, sizes={0xA: 0x8, 0xB: 0x40},
                    callers={0xA: range(12), 0xB: range(50)})
        self.assertEqual(rp.p2_getoradd(ctx, 0x1, ctx.callers_map()),
                         (0xA, None))

    def test_scb(self):
        ctx = mkctx(refs={rp.SCB_STR: {0xB001}},
                    callees={0xB001: {0xB002}})
        self.assertEqual(rp.p2_scb(ctx), (0xB002, None))


class TestSteamUiPickers(unittest.TestCase):
    def test_markapp(self):
        ctx = mkctx(refs={rp.MRU_STR: {0xC001}},
                    callees={0xC001: {0xC002}})
        self.assertEqual(rp.p2_markapp(ctx), (0xC002, None))

    def test_runframe_prev(self):
        ctx = mkctx(entries=[0xD001, 0xD002],
                    rstrings={0xD002: list(rp.COLDWANT)},
                    callees={0xD002: {0xD003}}, sizes={0xD001: 0x16})
        self.assertEqual(rp.p2_runframe(ctx, 0xD003), (0xD001, None))

    def test_shouldshow(self):
        F, B, T1, T2, S = 0xE010, 0xE020, 0xE011, 0xE012, 0xE013
        ctx = mkctx(callees={F: {T1, T2}, B: {F, S}, S: {T1}},
                    sizes={T1: 0x14, T2: 0x500})
        self.assertEqual(rp.p2_shouldshow(ctx, F, B, {}), (S, None))

    def test_getappid_cold_caller(self):
        F, G1, G2, C0 = 0xF010, 0xF011, 0xF012, 0xC0
        ctx = mkctx(callees={F: {G1, G2}, C0: {G1}},
                    callers={G1: range(205), G2: range(150)},
                    rstrings={C0: list(rp.COLDWANT)})
        self.assertEqual(rp.p2_getappid(ctx, F, ctx.callers_map()),
                         (G1, None))

    def test_lmwp_prev_tiny(self):
        ctx = mkctx(entries=[0x1001, 0x1002], sizes={0x1001: 0x10},
                    slots=[0x5], ff15={0x5: {0x1002}})
        self.assertEqual(rp.p2_lmwp(ctx), (0x1001, None))

    def test_gettopmgr(self):
        e = 0x2000
        img = Img()
        img.put(e + 0x20, bytes([0x48, 0x8B, 0x05, 1, 2, 3, 4, 0xC3]))
        ctx = mkctx(entries=[e, e + 0x30, 0x3000], img=img,
                    e8={e + 0x20: 594})
        self.assertEqual(rp.p2_gettopmgr(ctx), (e + 0x20, None))

    def test_rf32_scale_twin(self):
        t, s = 0x3001, 0x3002
        img = Img()
        key = bytes(range(27))
        img.put(t, key + bytes([(2 << 6) | 5]))
        img.put(s, key + bytes([(1 << 6) | 5]))
        ctx = mkctx(img=img, callees={0xF: {t}}, prefix={key: [t, s]})
        self.assertEqual(rp.p2_rf32(ctx, 0xF), (t, None))


class TestGetPackageInfo(unittest.TestCase):
    HOOK, DECOY = 0x4C9220, 0x4C9000

    def _ctx(self, bodies):
        img = Img()
        for rva, body in bodies:
            img.put(rva, body)
        return mkctx(entries=[r for r, _ in bodies], img=img)

    def test_unique_prologue_wins(self):
        good = rp.GPI_PREFIX + b"\x44\x8b\x49\x20" + b"\x90" * 32
        decoy = b"\x48\x89\x5c\x24\x19" + rp.GPI_PREFIX[5:] + b"\x90" * 32
        ctx = self._ctx([(self.DECOY, decoy), (self.HOOK, good)])
        self.assertEqual(rp.p2_getpackageinfo(ctx), (self.HOOK, None))

    def test_no_prologue_fails(self):
        ctx = self._ctx([(self.HOOK, b"\x90" * 64)])
        v, e = rp.p2_getpackageinfo(ctx)
        self.assertIsNone(v)
        self.assertIn("0 GetPackageInfo cands", e)

    def test_double_prologue_fails(self):
        good = rp.GPI_PREFIX + b"\x90" * 32
        ctx = self._ctx([(self.HOOK, good), (self.DECOY, good)])
        v, e = rp.p2_getpackageinfo(ctx)
        self.assertIsNone(v)
        self.assertIn("2 GetPackageInfo cands", e)


class TestProloguePin(unittest.TestCase):

    def test_keeps_only_pinned_starts(self):
        img = Img()
        img.put(0x1000, rp.CUBEC_PREFIX + b"\x90" * 8)
        img.put(0x2000, b"\x4c\x89\xa4\x24" + b"\x90" * 12)
        img.put(0x3000, rp.CUBEC_PREFIX[:4] + b"\x90" * 12)
        ctx = mkctx(img=img)
        self.assertEqual(rp.filter_prologue(ctx, {0x1000, 0x2000, 0x3000},
                                            rp.CUBEC_PREFIX), {0x1000})

    def test_unmapped_rva_dropped(self):
        img = Img()
        img.put(0x1000, rp.CUBEC_PREFIX + b"\x90" * 8)
        ctx = mkctx(img=img)
        self.assertEqual(rp.filter_prologue(ctx, {0x1000, 0x9999},
                                            rp.CUBEC_PREFIX), {0x1000})

    def test_empty_input(self):
        ctx = mkctx(img=Img())
        self.assertEqual(rp.filter_prologue(ctx, set(), rp.CUBEC_PREFIX), set())


class TestSourceRootNormalization(unittest.TestCase):

    def test_worker_prefix_collapsed(self):
        normal = (r"C:\buildworker\steam_rel_client_win64"
                  r"\build\src\public\tier1\utlmemory.h")
        hotfix = (r"C:\buildworker\steam_rel_client_hotfix_win64"
                  r"\build\src\public\tier1\utlmemory.h")
        self.assertEqual(rp.canon(normal), rp.canon(hotfix))
        self.assertEqual(rp.canon(normal),
                         rp.CS + r"public\tier1\utlmemory.h")

    def test_plain_string_untouched(self):
        self.assertEqual(rp.canon("num >= 0"), "num >= 0")


if __name__ == "__main__":
    unittest.main()
