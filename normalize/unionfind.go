package normalize

import "sort"

// UnionFind 是稳定标识上的并查集。
// 同一条观察中出现的所有 ip:/host: 标识被视为同一资产的别名，需要 union；
// 组件根由最小成员名确定，因此组件 ID 不依赖 union 的到达顺序。
type UnionFind struct {
	parent map[string]string
}

func NewUnionFind() *UnionFind {
	return &UnionFind{parent: map[string]string{}}
}

func (u *UnionFind) Add(id string) {
	if _, ok := u.parent[id]; !ok {
		u.parent[id] = id
	}
}

// Union 合并两个标识，返回组件当前代表。
func (u *UnionFind) Union(a, b string) {
	u.Add(a)
	u.Add(b)
	ra, rb := u.Find(a), u.Find(b)
	if ra == rb {
		return
	}
	// 让字典序小的作为父，保证代表稳定。
	if ra > rb {
		ra, rb = rb, ra
	}
	u.parent[rb] = ra
}

// UnionAll 合并一条观察中的全部标识。
func (u *UnionFind) UnionAll(ids []string) {
	if len(ids) == 0 {
		return
	}
	for _, id := range ids {
		u.Add(id)
	}
	root := ids[0]
	for _, id := range ids[1:] {
		u.Union(root, id)
	}
}

func (u *UnionFind) Find(x string) string {
	u.Add(x)
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]]
		x = u.parent[x]
	}
	return x
}

// Members 返回某组件的全部成员（有序）。
func (u *UnionFind) Members(root string) []string {
	var out []string
	for id := range u.parent {
		if u.Find(id) == root {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Components 返回 root -> members。
func (u *UnionFind) Components() map[string][]string {
	out := map[string][]string{}
	for id := range u.parent {
		r := u.Find(id)
		out[r] = append(out[r], id)
	}
	for r := range out {
		sort.Strings(out[r])
	}
	return out
}

// Snapshot 返回深拷贝。
func (u *UnionFind) Snapshot() *UnionFind {
	cp := NewUnionFind()
	for k, v := range u.parent {
		cp.parent[k] = v
	}
	return cp
}
