#!/usr/bin/env luajit

-- luaposix is recommended, as it allows safe interruptions:
local signal_ok, signal = pcall(require, 'posix.signal')

local FileSystem = {
  fat_numbers = 2,
  max_number_of_root_dirents = 0,  -- fat32 restriction
  terminate = false, -- used from signal handlers to cancel defragmentation
--[[ more fields:
  * fs: lua file object.
  * size: integer, filesystem size in bytes.
  set by check_bpb:
  * logical_sectors_per_cluster: one of 1, 2, 4, 8, 16, 32, 64 or 128.
  * reserved_logical_sectors: uint16_t, number of sectors before the fat.
  * total_logical_sectors: uint32_t, total number of sectors in the fs (including the BPB).
  * logical_sectors_per_fat: uint16_t, size of each FAT in sectors.
  * root_cluster_number: uint32_t, initial cluster number for the root directory.
  * fsi_sector_number: uint16_t, position of the FS Information Sector as absolute sector.
  * number_of_clusters: uint32_t, the number of clusters in the fs (number_of_clusters-1 is the last valid one)
  set by check_fsi:
  * last_known_free_clusters: uint32_t, approximation to the number of free clusters (cannot be trusted).
  * last_allocated_cluster: uint32_t, last allocated cluster number, used to improve free space search.
  set by check_fats:
  * fat: 0 based array of uint32_t fat entries.
  * dirty_fat_sectors: set of 0 based fat sectors, number -> true.
  * free_clusters: uint32_t how many free clusters are available.
  loaded by check_files:
  * extent_borders_to_dirents: map from the initial and last cluster numbers of the extent to the Dirent object.
]]
}
FileSystem.__index = FileSystem


local FAT_DATA_MOD = 0x10000000  -- so that we can ignore the upper 4 bits
local FAT_UNUSED_CLUSTER = 0
local FAT_RESERVED_CLUSTER = 1  -- it can be reserved when in the middle of a transaction.
local FAT_SPECIAL_RANGE = 0xFFFFFF0  -- fat entries with this value or higher are special
local FAT_BAD_CLUSTER = 0xFFFFFF7  -- pointing to a cluster with bad blocks (IO errors)
local FAT_END_OF_CHAIN = 0xFFFFFF8  -- fat entries with this value or higher mark the Last Cluster of the File.


--[[
Dirent:
  * parent: Dirent reference (or nil for root's dirent).
  * parent_index: 0 based index into parent's Dirent (or nil for root).
  * extents: array of pairs of inclusive cluster numbers.
  * dir: boolean
]]

local function format_unit(bytes)
  local units = {'B', 'kB', 'MB', 'GB'}
  local unit_index = 1
  local value = bytes
  while value >= 100000 and unit_index < #units do
    value = value / 1024
    unit_index = unit_index + 1
  end
  return ('%g %s'):format(value, units[unit_index])
end


local function format_extents(list)
  local strings = {}
  for i, range in ipairs(list) do
    strings[i] = ('%d-%d'):format(range[1], range[2])
  end
  return table.concat(strings, ', ')
end


function FileSystem:new(filename)
  local fd = assert(io.open(filename, 'r+b'))
  local size = assert(fd:seek 'end')

  local res = setmetatable({
    fd = fd,
    size = size, -- size in bytes
    extent_borders_to_dirents = {},
  }, self)

  res:check_bpb()
  res:check_fsi()
  res:check_fats()
  res:check_files{extents={{res.root_cluster_number, res.root_cluster_number}}, dir=true}
  return res
end


function FileSystem:check_bpb()
  -- reading first block to do some basic safety checks:
  --   * https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
  assert(self.fd:seek 'set')
  local bpb = assert(self.fd:read(0x200)) -- 200 bytes
  assert(bpb:byte() == 0xeb, 'This is probably not a FAT partition')

  print(('OEM Name:\t%q'):format(bpb:sub(0x003 + 1, 0x003 + 8)))

  local lo, hi = bpb:byte(0x00b + 1, 0x00b + 2)
  local bytes_per_logical_sector = 256 * hi + lo
  assert(bytes_per_logical_sector == 512, 'We do not support other values.')

  local logical_sectors_per_cluster = bpb:byte(0x00d + 1)
  print(('Logical sectors per cluster:\t%d (%d bytes)'):format(
      logical_sectors_per_cluster, logical_sectors_per_cluster * 512))

  lo, hi = bpb:byte(0x00e + 1, 0x00e + 2)
  local reserved_logical_sectors = 256 * hi + lo  -- includes the bpb sector!
  print(('Reserved logical sectors:\t%d (%d bytes)'):format(
      reserved_logical_sectors, reserved_logical_sectors * 512))

  local number_of_fats = bpb:byte(0x010 + 1)
  assert(number_of_fats == 2, 'Hardcoded for 2-FAT support only (1-FAT is really weird)')

  lo, hi = bpb:byte(0x011 + 1, 0x011 + 2)
  local max_number_of_root_dirents = 256 * hi + lo
  assert(max_number_of_root_dirents == 0, 'FAT32 requires max number of root directory entries to be 0.')

  lo, hi = bpb:byte(0x013 + 1, 0x013 + 2)
  local total_logical_sectors = 256 * hi + lo
  assert(total_logical_sectors == 0, 'FAT32 requires the total_logical_sectors word at 0x013 to be 0.')

  local media_descriptor = bpb:byte(0x015 + 1)
  print(('Media descriptor:\t0x%x (usually 0xf8)'):format(media_descriptor))
  assert(media_descriptor >= 0xf0, 'Wikipedia says so.')

  lo, hi = bpb:byte(0x016 + 1, 0x16 + 2)
  local logical_sectors_per_fat = 256 * hi + lo
  assert(logical_sectors_per_fat == 0, 'FAT32 requires the logical_sectors_per_fat word at 0x16 to be 0.')

  local hi2, hi3
  lo, hi, hi2, hi3 = bpb:byte(0x01c + 1, 0x01c + 4)
  local hidden_sectors_count = lo + 256 * (hi + 256 * (hi2 + 256 * hi3))
  --assert(hidden_sectors_count == 0,
  --  'I am not sure if this is strictly required but to be safe I require it,\n' ..
  --  'as I really do not know how to handle the non-zero case.')
  -- in theory we should be ok supporting "hidden sectors" as there should be no difference
  print(('Hidden sector count: %d (%s)'):format(
    hidden_sectors_count, format_unit(hidden_sectors_count * 512)))

  lo, hi, hi2, hi3 = bpb:byte(0x020 + 1, 0x020 + 4)
  total_logical_sectors = lo + 256 * (hi + 256 * (hi2 + 256 * hi3))
  print(('Total logical sectors: %d (%s)'):format(
      total_logical_sectors, format_unit(total_logical_sectors * 512)))
  assert(total_logical_sectors > 0, 'Even though MS-DOS supports reading the size from the MBR, we do not.')
  assert(total_logical_sectors * 512 == self.size, 'Usually it is, unless there was some resizing going on.')

  lo, hi, hi2, hi3 = bpb:byte(0x024 + 1, 0x024 + 4)
  logical_sectors_per_fat = lo + 256 * (hi + 256 * (hi2 + 256 * hi3))
  print(('Logical sectors per fat: %d (%s)'):format(
      logical_sectors_per_fat, format_unit(logical_sectors_per_fat * 512)))
  assert(logical_sectors_per_fat > 0)
  assert(hi2 ~= 0x28 and hi2 ~= 0x29, 'Could this be a non FAT32 filesystem?')

  lo, hi = bpb:byte(0x02a + 1, 0x02a + 2)
  assert(lo == 0 and hi == 0, 'Only version 0.0 is supported.')

  lo, hi, hi2, hi3 = bpb:byte(0x02c + 1, 0x02c + 4)
  local root_cluster_number = lo + 256 * (hi + 256 * (hi2 + 256 * hi3))
  assert(root_cluster_number > 0, 'If MS rejects root_cluster_number 0, so do we.')
  print('Root cluster number:', root_cluster_number)

  lo, hi = bpb:byte(0x030 + 1, 0x030 + 2)
  local fsi_sector_number = 256 * hi + lo
  print('FS Information sector number:', fsi_sector_number)
  print('Physical drive number:', bpb:byte(0x040 + 1))
  print(('Volume ID:\t%q'):format(bpb:sub(0x043 + 1, 0x043 + 4)))
  print(('Volume Label:\t%q'):format(bpb:sub(0x047 + 1, 0x047 + 8)))

  local filesystem_type = bpb:sub(0x052 + 1, 0x052 + 8)
  assert(filesystem_type == 'FAT32   ', 'Only FAT32 is supported here, not ' .. filesystem_type)

  local number_of_clusters_with_padding = (
    total_logical_sectors - reserved_logical_sectors - self.fat_numbers * logical_sectors_per_fat
    -- - math.ceil( 32*max_number_of_root_dirents/512 ) -- there are 0 special dirents in FAT32
  ) / logical_sectors_per_cluster
  local number_of_clusters = math.floor(number_of_clusters_with_padding)
  print(('Number of clusters: %d + (%d sectors) (%s)'):format(
      number_of_clusters,
      (number_of_clusters_with_padding - number_of_clusters) * logical_sectors_per_cluster,
      format_unit(number_of_clusters * logical_sectors_per_cluster * 512)))

  self.logical_sectors_per_cluster = logical_sectors_per_cluster
  self.reserved_logical_sectors = reserved_logical_sectors
  self.total_logical_sectors = total_logical_sectors
  self.logical_sectors_per_fat = logical_sectors_per_fat
  self.root_cluster_number = root_cluster_number
  self.fsi_sector_number = fsi_sector_number
  self.number_of_clusters = number_of_clusters
end


function FileSystem:check_fsi()
  -- https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#FS_Information_Sector
  assert(self.fd:seek('set', self.fsi_sector_number * 512))
  local fsi= assert(self.fd:read(0x200)) -- 200 bytes
  assert(fsi:sub(1, 4) == 'RRaA', 'RRaA!!! FSI signature not found.')
  assert(fsi:sub(0x1e4 + 1, 0x1e4 + 4) == 'rrAa', 'rrAa!!! FSI signature not found.')
  assert(fsi:sub(0x1fc + 1, 0x1fc + 4) == '\0\0U\170', '00_00_55_AA!!! FSI signature not found.')

  local lo, hi, hi2, hi3 = fsi:byte(0x1e8 + 1, 0x1e8 + 4)
  local last_known_free_clusters = lo + 256 * (hi + 256 * (hi2 + 256 * hi3))
  if last_known_free_clusters == 0xffffffff then
    print 'Free disk space not known yet'
  else
    print(('Last known free disk space:\t%d clusters (%s)'):format(
        last_known_free_clusters,
        format_unit(last_known_free_clusters * self.logical_sectors_per_cluster * 512)))
  end

  lo, hi, hi2, hi3 = fsi:byte(0x1ec + 1, 0x1ec + 4)
  local last_allocated_cluster = lo + 256 * (hi + 256 * (hi2 + 256 * hi3))
  print(('Last allocated data cluster:\t0x%x'):format(last_allocated_cluster))

  self.last_known_free_clusters = last_known_free_clusters
  self.last_allocated_cluster = last_allocated_cluster
end


function FileSystem:flush_fsi()
  -- we only need to write the last_allocated_cluster, as the free space shouldn't change:
  assert(self.fd:seek('set', self.fsi_sector_number * 512 + 0x1ec))
  assert(self.fd:write(string.char(
    self.last_allocated_cluster % 256,
    math.floor(self.last_allocated_cluster / 0x100) % 256,
    math.floor(self.last_allocated_cluster / 0x10000) % 256,
    math.floor(self.last_allocated_cluster / 0x1000000))))
end


function FileSystem:check_fats()
  local fat_offset = 512 * self.reserved_logical_sectors
  assert(assert(self.fd:seek('set', fat_offset)) == fat_offset)

  local fat1 = self.fd:read(512 * self.logical_sectors_per_fat)
  local fat2 = self.fd:read(512 * self.logical_sectors_per_fat)
  assert(fat1 == fat2, 'FATs differ! run fsck/scandisk/chkdsk before continuing')

  local free_clusters = 0
  local free_ranges = {} -- array of inclusive pairs
  local fat = {}  -- 0 based array of 32-bit unsigned integers

  for i = 0, 512 * self.logical_sectors_per_fat / 4 - 1 do
    local lo, hi, hi2, hi3 = fat1:byte(4*i + 1, 4*i + 4)
    local fat_entry = lo + 256 * (hi + 256 * (hi2 + 256 * hi3))
    fat[i] = fat_entry

    if 2 <= i and i < self.number_of_clusters then
      local fat_entry_data = fat_entry % FAT_DATA_MOD
      -- since we are already traversing the FAT, let's calculate the free space
      if fat_entry_data == FAT_UNUSED_CLUSTER then
        free_clusters = free_clusters + 1
        if #free_ranges > 0 and free_ranges[#free_ranges][2] == i-1 then
          -- increase last range:
          free_ranges[#free_ranges][2] = i
        else
          -- add a new range:
          free_ranges[#free_ranges + 1] = {i, i}
        end
      end
    end
  end
  assert(fat[self.number_of_clusters - 1], 'Last claster should be present!')

  -- ensure bits 27 and 26 are set:
  assert(fat[1] % FAT_DATA_MOD >= FAT_DATA_MOD/2, 'Dirty filesystem! make sure it is not mounted?')
  assert(fat[1] % (FAT_DATA_MOD/2) >= FAT_DATA_MOD/4, 'Filesystem with IO errors, make sure to run fsck/scandisk/chkdsk')

  -- the 2 initial clusters be counted as part of the used space?:
  print(('Used disk space:\t2 initial special clusters + %d data clusters (%s of data)'):format(
    self.number_of_clusters - 2 - free_clusters,
    format_unit((self.number_of_clusters - 2 - free_clusters) * self.logical_sectors_per_cluster * 512)))
  print(('Free disk space:\t%d clusters (%s)'):format(
    free_clusters, format_unit(free_clusters * self.logical_sectors_per_cluster * 512)))
  print('Free disk space ranges:', format_extents(free_ranges))

  assert(free_clusters >= 10, 'Cannot (reasonably) defragment without at least 10 free cluster.')

  self.fat = fat
  self.dirty_fat_sectors = {}  -- set of 0 based fat sectors: number -> true
  self.free_clusters = free_clusters
end


function FileSystem:get_fat_entry(index)
  return self.fat[index] % FAT_DATA_MOD
end


function FileSystem:set_fat_entry(index, value)
  assert(0 <= index and index < FAT_DATA_MOD, 'Fat index out of range.')
  if self.fat[index] == value then return end
  -- not the most efficient alternative, but a very compatible one (keeping the higher bits):
  self.fat[index] = math.floor(self.fat[index] / FAT_DATA_MOD) * FAT_DATA_MOD + value % FAT_DATA_MOD
  self.dirty_fat_sectors[math.floor(index / 128)] = true
end


function FileSystem:flush_fat()
  local fat_entries = {}
  for sector_offset in pairs(self.dirty_fat_sectors) do
    for i = 0, 127 do
      local fat_entry = self.fat[128 * sector_offset + i]
      local lo = fat_entry % 256
      local hi = math.floor(fat_entry / 0x100) % 256
      local hi2 = math.floor(fat_entry / 0x10000) % 256
      local hi3 = math.floor(fat_entry / 0x1000000)
      fat_entries[i + 1] = string.char(lo, hi, hi2, hi3)
    end
    local binary_data_string = table.concat(fat_entries)
    for fat_number = 0, self.fat_numbers - 1 do
      local fat_offset = 512 * (
        self.reserved_logical_sectors + sector_offset + fat_number * self.logical_sectors_per_fat)
      assert(assert(self.fd:seek('set', fat_offset)) == fat_offset)
      assert(self.fd:write(binary_data_string))
    end
  end
  self.fd:flush()
  self.dirty_fat_sectors = {}
end


function FileSystem:check_files(dirent, filename)
  print(('Filename:\t%q\t\t\t(first cluster = %d, parent_index = %s)'):format(
    filename or '/', dirent.extents[1][1], dirent.parent_index))

  if #dirent.extents == 0 or dirent.extents[1][1] == 0 then return end
  self.extent_borders_to_dirents[dirent.extents[1][1]] = dirent

  local last_extent = dirent.extents[#dirent.extents]
  local children_index = 0

  local function read_cluster()
    if not dirent.dir then return end

    assert(self.fd:seek('set', self:cluster_offset(last_extent[2])))
    local cluster_size = 512 * self.logical_sectors_per_cluster
    local cluster_data = assert(self.fd:read(cluster_size))
    assert(#cluster_data == cluster_size, 'Short read on cluster')

    for i = 0, cluster_size - 1, 32 do
      local first_byte = cluster_data:byte(i + 1)
      local attributes = cluster_data:byte(i + 0x0b + 1)
      local is_volume = attributes % 0x10 >= 0x08
      local is_directory = attributes % 0x20 >= 0x10

      -- 0: entry is available and no subsequent entry is in use:
      if first_byte == 0 then return end

      -- 0x2e is used on '.' and '..' dirents, 0xe5 is used for deleted files.
      if not is_volume and first_byte ~= 0x2e and first_byte ~= 0xe5 then
        local child_name = ('%s/%s%s%s'):format(filename or '',
          cluster_data:sub(i+1, i+8):match '[^ ]*',
          cluster_data:byte(i+0x08+1) == 32 and '' or '.',
          cluster_data:sub(i+0x08+1, i+0x08+3):match '[^ ]*')

        -- upper word of first cluster:
        local lo, hi = cluster_data:byte(i + 0x014 + 1, i + 0x14 + 2)
        local first_cluster = 256 * hi + lo

        -- lower word of first cluster:
        lo, hi = cluster_data:byte(i + 0x01a + 1, i + 0x1a + 2)
        first_cluster = 65536 * first_cluster + 256 * hi + lo

        self:check_files({
          parent = dirent,
          parent_index = children_index,
          extents = {{first_cluster, first_cluster}},
          dir = is_directory,
        }, child_name)
      end
      children_index = children_index + 1
    end
  end

  local next_cluster = self:get_fat_entry(last_extent[2])
  read_cluster()
  while 0 < next_cluster and next_cluster < FAT_BAD_CLUSTER do
    read_cluster()

    if next_cluster == last_extent[2] + 1 then
      last_extent[2] = last_extent[2] + 1
    else
      self.extent_borders_to_dirents[last_extent[2]] = dirent
      self.extent_borders_to_dirents[next_cluster] = dirent
      last_extent = {next_cluster, next_cluster}
      dirent.extents[#dirent.extents + 1] = last_extent
    end
    next_cluster = self:get_fat_entry(last_extent[2])
  end
  self.extent_borders_to_dirents[last_extent[2]] = dirent
  if #dirent.extents > 1 then
    print(('Fragmented file %q with %d extents: %s'): format(
      filename or '/', #dirent.extents, format_extents(dirent.extents)))
  end
end


function FileSystem:defragment()
  -- Iterate through all the clusters applying the following rules:
  -- 1. if the cluster is the continuation of the previous one, then CONTINUE WITH NEXT CLUSTER
  -- 2. if the current cluster is in use and (
  --      if the last file before this cluster had additional clusters, or
  --      if the current cluster is being in use by a subsequent cluster of a file), then
  --    move the data at the cluster to any free position, with current cluster marked as free.
  -- 3. if the last file before this cluster had additional clusters, move the next one to the
  --    current cluster, then CONTINUE WITH NEXT CLUSTER
  -- 4. select the next initial cluster of any file and move it to the current cluster, then
  --    CONTINUE WITH NEXT CLUSTER.
  -- 5. otherwise END, as the current file is finished and there are no more initial clusters.
  --
  -- By applying these rules we have as a side effect the fact that files before the current
  -- cluster at any time are completely defragmented (with the exception of the current last file).
  local completed = false

  local function defragment(cluster)
    io.write('Defragmenting cluster ', cluster, ': ')
    io.flush()
    -- FIRST RULE: skip when not fragmented.
    if cluster > 2 then
      if self:get_fat_entry(cluster - 1) == cluster then
        print 'OK, cluster already defragmented.'
        return
      end
    end

    -- SECOND RULE: free the current cluster if needed
    local next_cluster = self:get_fat_entry(cluster)
    local previous_dirent, next_cluster_of_previous_dirent
    local extra_message = ''
    if cluster > 2 then
      previous_dirent = assert(self.extent_borders_to_dirents[cluster - 1],
        'missing previous dirent in extent borders, something went really bad, sorry!')
      assert(previous_dirent.extents[1][2] == cluster - 1,
        'expecting previous cluster on first extent border of the previous dirent')
      if previous_dirent.extents[2] then
        next_cluster_of_previous_dirent = previous_dirent.extents[2][1]
        assert(next_cluster_of_previous_dirent > cluster,
          'the extents for previous dirent were not merged')
      end
    end

    if next_cluster ~= FAT_UNUSED_CLUSTER then  -- aka "if cluster in use":
      local dirent_using_current_cluster = self.extent_borders_to_dirents[cluster]
      if not dirent_using_current_cluster then
        error(('did we reach a reserved cluster? cluster %d, fat entry 0x%x'):format(
          cluster, next_cluster))
      end

      if not next_cluster_of_previous_dirent and dirent_using_current_cluster.extents[1][1] == cluster then
        -- the previous file was completed and we are starting a new file!
        print 'OK, previous file was completed. Continuing with next file.'
        return
      end
      -- free the current cluster!
      local free_cluster = self:find_free_cluster()
      self:move_cluster(dirent_using_current_cluster, cluster, free_cluster)
      extra_message = (' (after freeing to %d)'):format(free_cluster)
    end

    -- THIRD RULE: bring back the next cluster of the previous file
    if next_cluster_of_previous_dirent then
      self:move_cluster(previous_dirent, next_cluster_of_previous_dirent, cluster)
      print(('OK, subsequent cluster was brought from %d%s.'):format(
        next_cluster_of_previous_dirent, extra_message))
      return
    end

    -- FOURTH RULE: select the next initial segment of any file
    local next_dirent
    for next_initial_cluster = cluster + 1, self.number_of_clusters - 1 do
      local dirent = self.extent_borders_to_dirents[next_initial_cluster]
      -- we are only looking for initial segments:
      if dirent and next_initial_cluster == dirent.extents[1][1] then
        next_dirent = dirent
        break
      end
    end
    if next_dirent then
      self:move_cluster(next_dirent, next_dirent.extents[1][1], cluster)
      print(('OK, the initial cluster of a new file was brought from %d%s.'):format(
        next_dirent.extents[1][1], extra_message))
      return
    end

    -- FIFTH RULE: END
    print 'OK, defragmentation completed.'
    self:flush_fsi()
    completed = true
    return
  end

  for cluster = 2, self.number_of_clusters - 1 do
    defragment(cluster)
    if completed or self.terminate then break end
  end
  self:flush_fat()
end


--- This operation moves a single cluster of a single dirent, it should be atomic and the
-- filesystem should be consistent in memory after it's completed (or at disk after the fat is
-- flushed).
--   In this function special care is taken to update the parent dirents when we are moving the
-- first cluster of a dirent.
--
-- @param dirent Dirent object to update.
-- @param origin_cluster cluster number that should be part of the referenced dirent.
-- @param destination_cluster cluster number of a free cluster.
function FileSystem:move_cluster(dirent, origin_cluster, destination_cluster)
  -- Safety Checks:
  assert(origin_cluster ~= destination_cluster, 'Why would you move the file otherwise?')
  assert(self:get_fat_entry(destination_cluster) == FAT_UNUSED_CLUSTER,
    'Destination_cluster must be free.')
  local origin_next_cluster = self:get_fat_entry(origin_cluster)
  assert(origin_next_cluster ~= FAT_UNUSED_CLUSTER, 'Wut? origin_cluster must not be free')

  -- Calculate Extents (merging if it's the case)
  local new_extents = {}
  local function add_to_new_extents(from, to)
    assert(from <= to, 'Valid extents have from < to')
    local last_extent = new_extents[#new_extents]
    if last_extent and last_extent[2] + 1 == from then
      -- let's merge!
      last_extent[2] = to
    else
      new_extents[#new_extents + 1] = {from, to}
    end
  end
  local previous_cluster
  local origin_cluster_found_in_extents = false
  for i, pair in ipairs(dirent.extents) do
    if pair[1] <= origin_cluster and origin_cluster <= pair[2] then
      origin_cluster_found_in_extents = true
      -- break pair, adding new extent in the middle (may or may not fragment):
      if pair[1] < origin_cluster then
        add_to_new_extents(pair[1], origin_cluster - 1)
        previous_cluster = origin_cluster - 1
      elseif i > 1 then
        previous_cluster = dirent.extents[i-1][2]
      end
      add_to_new_extents(destination_cluster, destination_cluster)
      if origin_cluster < pair[2] then
        add_to_new_extents(origin_cluster + 1, pair[2])
      end
    else -- out of range:
      add_to_new_extents(pair[1], pair[2])
    end
  end

  -- Final Safety check:
  assert(origin_cluster_found_in_extents, 'Wut? origin_cluster was not found in the file extents')

  -- ok, no going back!
  -- this may not be the most efficient way to update extent_borders_to_dirents, but it works:
  for _, pair in ipairs(dirent.extents) do
    self.extent_borders_to_dirents[pair[1]] = nil
    self.extent_borders_to_dirents[pair[2]] = nil
  end
  for _, pair in ipairs(new_extents) do
    self.extent_borders_to_dirents[pair[1]] = dirent
    self.extent_borders_to_dirents[pair[2]] = dirent
  end
  dirent.extents = new_extents

  -- Copy data!
  assert(self.fd:seek('set', self:cluster_offset(origin_cluster)))
  local cluster_size = 512 * self.logical_sectors_per_cluster
  local cluster_data = assert(self.fd:read(cluster_size))
  assert(#cluster_data == cluster_size, 'Short read on cluster')

  assert(self.fd:seek('set', self:cluster_offset(destination_cluster)))
  assert(self.fd:write(cluster_data))

  -- If it's the first cluster of the file:
  if not previous_cluster then
    if dirent.parent then
      -- Update parent's parent_index pointer
      local dirents_per_cluster = 512 * self.logical_sectors_per_cluster / 32
      local parent_index_cluster_offset = math.floor(dirent.parent_index / dirents_per_cluster)
      local cluster_to_update
      for i, pair in ipairs(dirent.parent.extents) do
        if pair[1] + parent_index_cluster_offset <= pair[2] then
          cluster_to_update = pair[1] + parent_index_cluster_offset
          break
        else
          local clusters_in_pair = pair[2] - pair[1] + 1
          parent_index_cluster_offset = parent_index_cluster_offset - clusters_in_pair
        end
      end
      assert(cluster_to_update, 'Wut? have we lost the parent cluster pointing to this child???')

      local parent_index_offset_into_cluster = dirent.parent_index % dirents_per_cluster * 32
      self:update_dirent_pointer(cluster_to_update, parent_index_offset_into_cluster,
        origin_cluster, destination_cluster)
    else
      -- If we are moving the root directory, update the cluster_number at the BPB
      assert(self.fd:seek('set', 0x02c))
      local lo, hi, hi2, hi3 = assert(self.fd:read(4)):byte(0x02c + 1, 0x02c + 4)
      local old_root_cluster_number = lo + 256 * (hi + 256 * (hi2 + 256 * hi3))
      assert(old_root_cluster_number == origin_cluster,
        'Inconsistency detected moving root directory, restore backup and debug.')

      assert(self.fd:seek('set', 0x02c))
      assert(self.fd:write(string.char(
        destination_cluster % 256,
        math.floor(destination_cluster / 0x100) % 256,
        math.floor(destination_cluster / 0x10000) % 256,
        math.floor(destination_cluster / 0x1000000))))
    end
    if dirent.dir then
      -- if we are moving a directory, update "." reference and all children's ".." references
      self:traverse_dir_dirent_direntries(dirent, function(callback_data)
        if callback_data.first_byte == 0x2e then
          if callback_data.second_byte == 32 then
            -- we have found the '.' entry, let's update it:
            self:update_dirent_pointer(
              callback_data.cluster_number,
              callback_data.byte_offset_into_cluster,
              origin_cluster,
              destination_cluster)
          end
        elseif callback_data.is_directory and callback_data.first_cluster ~= FAT_UNUSED_CLUSTER then
          -- Note: this is an "elseif" to avoid an infinite loop traversing '.' or '..'
          -- Now update the ".." of any non-empty subdirectory.
          local inner_dirent = self.extent_borders_to_dirents[callback_data.first_cluster]
          assert(inner_dirent, 'A new inner directory appears, then I took an arrow to the knee!')

          self:traverse_dir_dirent_direntries(inner_dirent, function(inner_callback_data)
            if inner_callback_data.first_byte == 0x2e and inner_callback_data.second_byte == 0x2e then
              self:update_dirent_pointer(
                inner_callback_data.cluster_number,
                inner_callback_data.byte_offset_into_cluster,
                origin_cluster,
                destination_cluster)
            end
          end)
        end
      end)
    end
  end

  -- update the FAT:
  self:set_fat_entry(origin_cluster, FAT_UNUSED_CLUSTER)
  if previous_cluster then
    self:set_fat_entry(previous_cluster, destination_cluster)
  end
  self:set_fat_entry(destination_cluster, origin_next_cluster)
end


--- Traverses a directory calling callback for each child.
-- callback is called with an object containing:
--   * cluster_number: uint32_t, the cluster cluster where the child dirent is located
--   * byte_offset_into_cluster: uint32_t, the position of the child dirent from the cluster
--   * first_byte: uint8_t, first byte of the child dirent
--   * second_byte: uint8_t, second byte of the child dirent
--   * is_directory: boolean, if the child dirent is a directory
--   * first_cluster: uint32_t, initial cluster where the dirent points to
--
function FileSystem:traverse_dir_dirent_direntries(dirent, callback)
  assert(dirent.dir, 'Dirent must be a dir dirent to be traversable')

  local cluster_size = 512 * self.logical_sectors_per_cluster
  local callback_data = {}
  for _, pair in ipairs(dirent.extents) do
    for cluster_number = pair[1], pair[2] do
      callback_data.cluster_number = cluster_number
      self.fd:seek('set', self:cluster_offset(cluster_number))
      local cluster_data = self.fd:read(cluster_size)

      for i = 0, cluster_size - 1, 32 do
        callback_data.byte_offset_into_cluster = i
        callback_data.first_byte = cluster_data:byte(i + 1)
        callback_data.second_byte = cluster_data:byte(i + 2)
        local attributes = cluster_data:byte(i + 0x0b + 1)
        local is_volume = attributes % 0x10 >= 0x08
        callback_data.is_directory = attributes % 0x20 >= 0x10

        local lo, hi = cluster_data:byte(i + 0x14 + 1, i + 0x14 + 2) -- upper word
        callback_data.first_cluster = 256 * hi + lo
        lo, hi = cluster_data:byte(i + 0x01a + 1, i + 0x1a + 2) -- lower word
        callback_data.first_cluster = 65536 * callback_data.first_cluster + 256 * hi + lo

        if callback_data.first_byte == 0 then return end -- last direntry

        if not is_volume and callback_data.first_byte ~= 0xe5 then
          -- not is a volume, and not is deleted, then call the callback
          if callback(callback_data) == 'break' then
            return
          end
        end
      end
    end
  end
end


function FileSystem:update_dirent_pointer(
  cluster_number, byte_offset_into_cluster, old_first_cluster_pointer, new_first_cluster_pointer
)
  -- Let's first read the dirent as a basic sanity check:
  local absolute_dirent_offset = self:cluster_offset(cluster_number) + byte_offset_into_cluster
  assert(self.fd:seek('set', absolute_dirent_offset))
  local dirent_string = assert(self.fd:read(32))
  assert(#dirent_string == 32)

  -- upper word of first cluster:
  local lo, hi = dirent_string:byte(0x014 + 1, 0x14 + 2)
  local first_cluster = 256 * hi + lo

  -- lower word of first cluster:
  lo, hi = dirent_string:byte(0x01a + 1,0x1a + 2)
  first_cluster = 65536 * first_cluster + 256 * hi + lo

  assert(first_cluster == old_first_cluster_pointer,
    'Unexpected different old first cluster pointer, this is a serious internal error.')

  -- update upper 2 bytes (LE)
  assert(self.fd:seek('set', absolute_dirent_offset + 0x014))
  assert(self.fd:write(string.char(
    math.floor(new_first_cluster_pointer / 0x10000) % 256,
    math.floor(new_first_cluster_pointer / 0x1000000))))

  -- lower 2 bytes (LE)
  assert(self.fd:seek('set', absolute_dirent_offset + 0x01a))
  assert(self.fd:write(string.char(
    new_first_cluster_pointer % 256,
    math.floor(new_first_cluster_pointer / 0x100))))
end


function FileSystem:find_free_cluster()
  local cluster = self.last_allocated_cluster
  local looped = false
  while self:get_fat_entry(cluster) == FAT_UNUSED_CLUSTER and cluster > 2 do
    cluster = cluster - 1
  end
  while self:get_fat_entry(cluster) ~= FAT_UNUSED_CLUSTER do
    cluster = cluster + 1
    if cluster >= self.number_of_clusters then
      assert(not looped, 'There is no free space!!!')
      looped = true
      cluster = 2
    end
  end
  self.last_allocated_cluster = cluster
  return cluster
end


function FileSystem:cluster_offset(cluster_number)
  return 512 * (
    self.reserved_logical_sectors
    + self.fat_numbers * self.logical_sectors_per_fat
    -- + math.ceil( 32*self.max_number_of_root_dirents/512 ) -- there are 0 special dirents in FAT32
    + (cluster_number - 2) * self.logical_sectors_per_cluster
  )
end


local fs = FileSystem:new(arg[1])
if arg[2] == 'defragment' then
  if signal_ok then
    signal.signal(signal.SIGINT, function()
      fs.terminate = true
    end)
  else
    print '                    "posix.signal" package was not found.'
    print 'So do NOT interrupt (^C) the process while defragmenting,'
    print 'unless you wanna end with a broken filesystem.'
    print ''
    print 'Press enter to defragment (or ^C to cancel).'
    io.read()
  end

  fs:defragment()
  fs.fd:close()
end
