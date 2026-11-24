import { Button, Card, GrdrIcon, Heading, Text, VStack } from "@grdr/ui";

export function InsightTile({
  metric,
  headline,
  comparison,
  actionLabel,
  onAction,
}: {
  metric: string;
  headline: string;
  comparison: string;
  actionLabel: string;
  onAction: () => void;
}) {
  return (
    <Card padding={3}>
      <VStack gap={2}>
        <Heading level={2} className="tabular">
          {metric}
        </Heading>
        <Text>{headline}</Text>
        <Text type="supporting" color="secondary" size="sm">
          {comparison}
        </Text>
        <div>
          <Button
            variant="ghost"
            size="sm"
            label={actionLabel}
            endContent={<GrdrIcon name="arrow-right" size={13} />}
            onClick={onAction}
          />
        </div>
      </VStack>
    </Card>
  );
}
