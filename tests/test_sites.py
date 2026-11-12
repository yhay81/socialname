from pathlib import Path

import socialname


def test_bundled_catalog_loads_with_one_linktree_profile():
    catalog = Path(socialname.__file__).parent / "resources" / "data.json"
    sites = socialname.create_sites_info(str(catalog))

    assert [name for name in sites if name.casefold() == "linktree"] == ["Linktree"]
    assert sites["Linktree"].url_user.format("example") == "https://linktr.ee/example"
