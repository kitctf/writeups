Rubinius::CodeLoader.require_compiled './cipher'
Rubinius::CodeLoader.require_compiled './trie'

$c = Cipher.new("KDwXH3e1SBgayvI6uWC09bzTAqU4OoENrnmdkxPtRsJLfhZjY57lpc28MVGi QF".chars.to_a)
t = Marshal.load(File.read('trie.dump'))
class Trie
  attr_reader :root
  class Node
    def walk(path="")
      path = path + @char
      if @end
        puts $c.decrypt(path) + ' => ' + @value
      end
      @left.walk(path) if @left
      @mid.walk(path) if @mid
      @right.walk(path) if @right
    end
  end
end
t.root.walk
