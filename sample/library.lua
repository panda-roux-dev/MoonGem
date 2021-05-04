local impl = { n = 0 }

function impl:add(a, b)
  self.n = self.n + 1
  return a + b
end

return impl
