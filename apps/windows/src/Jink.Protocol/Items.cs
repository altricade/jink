using System.Collections;

namespace Jink.Protocol;

/// <summary>A read-only list that equals another with the same items in the
/// same order, so that records holding lists compare by value.</summary>
/// <typeparam name="T">The items.</typeparam>
public sealed class Items<T> : IReadOnlyList<T>, IEquatable<Items<T>>
{
    private readonly T[] items;

    /// <summary>A list of <paramref name="items"/> (copied).</summary>
    public Items(IEnumerable<T> items)
    {
        this.items = [.. items];
    }

    /// <inheritdoc/>
    public int Count => items.Length;

    /// <inheritdoc/>
    public T this[int index] => items[index];

    /// <inheritdoc/>
    public IEnumerator<T> GetEnumerator() => ((IEnumerable<T>)items).GetEnumerator();

    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => items.GetEnumerator();

    /// <inheritdoc/>
    public bool Equals(Items<T>? other) =>
        other is not null && items.AsSpan().SequenceEqual(other.items, EqualityComparer<T>.Default);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as Items<T>);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = default(HashCode);
        foreach (var item in items)
        {
            hash.Add(item);
        }

        return hash.ToHashCode();
    }

    /// <inheritdoc/>
    public override string ToString() => $"[{string.Join(", ", items)}]";
}

/// <summary>Makes <see cref="Items{T}"/>.</summary>
public static class Items
{
    /// <summary>A list of <paramref name="items"/>.</summary>
    /// <typeparam name="T">The items.</typeparam>
    public static Items<T> Of<T>(params ReadOnlySpan<T> items) => new(items.ToArray());
}
